#include <sstream>
#include "HomeKey.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "nvs.h"
#include <util/utils.h>
#include "HAP.h"

extern nvs_handle savedData;
extern homeKeyReader::readerData_t readerData;
extern bool defaultToStd;

void deleteReaderData(__attribute__((unused)) const char *buf)
{
    const char *TAG = "deleteReaderData";
    readerData.issuers.clear();
    std::fill(readerData.identifier, readerData.identifier + 8, 0);
    std::fill(readerData.reader_identifier, readerData.reader_identifier + 8, 0);
    std::fill(readerData.reader_private_key, readerData.reader_private_key + 32, 0);
    esp_err_t erase_nvs = nvs_erase_key(savedData, "READERDATA");
    esp_err_t commit_nvs = nvs_commit(savedData);
    ESP_LOGI(TAG, "*** NVS W STATUS");
    ESP_LOGI(TAG, "ERASE: %s", esp_err_to_name(erase_nvs));
    ESP_LOGI(TAG, "COMMIT: %s", esp_err_to_name(commit_nvs));
    ESP_LOGI(TAG, "*** NVS W STATUS");
}

void pairCallback(bool isPaired)
{
    if (!isPaired && HAPClient::nAdminControllers() == 0)
    {
        deleteReaderData(nullptr);
    }
}

void setFlow(const char *buf)
{
    const char *TAG = "setFlow";
    switch (buf[1])
    {
        case '0':
            defaultToStd = false;
            ESP_LOGI(TAG, "FAST Flow");
            break;

        case '1':
            defaultToStd = true;
            ESP_LOGI(TAG, "STANDARD Flow");
            break;

        default:
            ESP_LOGI(TAG, "0 = FAST flow, 1 = STANDARD Flow");
            break;
    }
}

void setMqttConfiguration(const char *buf) {
    const char *TAG = "setMqttConfiguration";

    if ( strlen(buf) == 1 ) {
        ESP_LOGW(TAG, "Expected: @M<host>:<port> <username>:<password> [<client_id>]");
        return;
    }

    // TODO: M<host>:<port> <username>:<password> [<client_id>]
    mqttData_t data;

    char *strPtr = const_cast<char *>(buf);
    char *token;

    strPtr++; // skip the command character

    token = strsep(&strPtr, ":");
    ESP_LOGD(TAG, "Name: '%s'", token);
    strcpy(data.mqtt_host, token);

    token = strsep(&strPtr, " ");
    ESP_LOGD(TAG, "Port: '%s'", token);
    data.mqtt_port = atoi(token);

    token = strsep(&strPtr, ":");
    ESP_LOGD(TAG, "Username: '%s'", token);
    strcpy(data.mqtt_username, token);

    token = strsep(&strPtr, " ");
    ESP_LOGD(TAG, "Password: '%s'", token);
    strcpy(data.mqtt_password, token);

    token = strsep(&strPtr, "\n");
    if ( token != nullptr ) {
        // could be empty
        ESP_LOGI(TAG, "Client Id: '%s'", token);
        strcpy(data.mqtt_client_id, token);
    }

    // TODO: add confirm set

    ESP_LOGI(TAG, "Storing mqtt: %s@%s:%i", data.mqtt_username, data.mqtt_host, data.mqtt_port);

    esp_err_t ret = nvs_set_blob(savedData, "MQTTDATA", &data, sizeof(data));
    if ( ret != ESP_OK ) {
        // TODO
    }
    ret = nvs_commit(savedData);
    if ( ret != ESP_OK ) {
        // TODO
    }

    // TODO: restart mqtt or reboot?
}

void setLogLevel(const char *buf)
{
    const char *TAG = "setLogLevel";
    esp_log_level_t level = esp_log_level_get("*");

    switch (buf[1]) {
        case 'E':
            level = ESP_LOG_ERROR;
            break;
        case 'W':
            level = ESP_LOG_WARN;
            break;
        case 'I':
            level = ESP_LOG_INFO;
            break;
        case 'D':
            level = ESP_LOG_DEBUG;
            break;
        case 'V':
            level = ESP_LOG_VERBOSE;
            break;
        case 'N':
            level = ESP_LOG_NONE;
            break;
        default:
            ESP_LOGI(TAG, "Unknown log level: '%c' (should be one of 'E', 'W', 'I', 'D', 'V', 'N')", buf[1]);
    }
    ESP_LOGI(TAG, "Log level set to %i", level);
    esp_log_level_set("*", level);
}

void insertDummyIssuers(const char *buf)
{
    const char *TAG = "insertDummyIssuers";
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
    unsigned int iterations = atoi(&buf[1]);
    if (iterations > 64)
    {
        ESP_LOGW(TAG, "Invalid Argument: @I<num> (where num <= 64)");
        return;
    }
    for (size_t i = 0; i < iterations; i++)
    {
        mbedtls_ecp_keypair ephemeral;
        mbedtls_ecp_keypair_init(&ephemeral);
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &ephemeral, mbedtls_ctr_drbg_random, &drbg);
        std::vector<uint8_t> bufPub;
        bufPub.resize(MBEDTLS_ECP_MAX_BYTES);
        bufPub.reserve(MBEDTLS_ECP_MAX_BYTES);
        size_t olen = 0;
        mbedtls_ecp_point_write_binary(&ephemeral.grp, &ephemeral.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, bufPub.data(), bufPub.capacity());
        bufPub.resize(olen);
        mbedtls_ecp_keypair_free(&ephemeral);

        size_t buffer_size_x = mbedtls_mpi_size(&ephemeral.Q.X);
        std::vector<uint8_t> X;
        X.resize(buffer_size_x);
        X.reserve(buffer_size_x);
        mbedtls_mpi_write_binary(&ephemeral.Q.X, X.data(), buffer_size_x);

        homeKeyIssuer::issuer_t issuer;
        memcpy(issuer.issuerId, utils::getHashIdentifier(bufPub.data(), 32, true).data(), 8);
        memcpy(issuer.issuer_key_x, X.data(), X.size());
        memcpy(issuer.publicKey, bufPub.data(), bufPub.size());
        homeKeyEndpoint::endpoint_t endpoint;
        endpoint.counter = 0;
        memcpy(endpoint.endpoint_key_x, X.data(), X.size());
        memcpy(endpoint.endpointId, utils::getHashIdentifier(bufPub.data(), 32, false).data(), 6);
        endpoint.key_type = 0;
        endpoint.last_used_at = 0;
        endpoint.enrollments.attestation.payload.resize(64);
        endpoint.enrollments.attestation.unixTime = 0;
        endpoint.enrollments.hap.payload.resize(64);
        endpoint.enrollments.hap.unixTime = 0;
        esp_fill_random(endpoint.persistent_key, 32);
        memcpy(endpoint.publicKey, bufPub.data(), bufPub.size());
        issuer.endpoints.emplace_back(endpoint);
        issuer.endpoints.emplace_back(endpoint);
        issuer.endpoints.emplace_back(endpoint);
        issuer.endpoints.emplace_back(endpoint);

        readerData.issuers.emplace_front(issuer);
    }
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&drbg);
}

void printIssuers(__attribute__((unused)) const char *buf)
{
    const char *TAG = "printIssuers";
    ESP_LOGI(TAG, "HOMEKEY ISSUERS: %d", readerData.issuers.size());
    for (auto &issuer : readerData.issuers)
    {
        ESP_LOGI(TAG, "Issuer ID: %s, Public Key: %s",
                 utils::bufToHexString(issuer.issuerId, sizeof(issuer.issuerId)).c_str(),
                 utils::bufToHexString(issuer.publicKey, sizeof(issuer.publicKey)).c_str());
        for (auto &endpoint : issuer.endpoints)
        {
            ESP_LOGI(TAG, "    Endpoint ID: %s, Public Key: %s",
                     utils::bufToHexString(endpoint.endpointId, sizeof(endpoint.endpointId)).c_str(),
                     utils::bufToHexString(endpoint.publicKey, sizeof(endpoint.publicKey)).c_str());
        }
    }
}
