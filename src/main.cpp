#include <auth/authContext.h>
#include <HomeKey.h>
#include <util/utils.h>
#include "HomeSpan.h"
#include "TLV.h"
#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>
#include "PN532.h"
#include <list>
#include <util/BERTLV.h>
#include "HAP.h"
#include <mbedtls/sha1.h>
#include <mbedtls/error.h>
#include <mbedtls/asn1write.h>
#include <sstream>
#include <PicoMQTT.h>
#include <ESPmDNS.h>

#include "HomeKey_setup.h"
#include "span_commands.h"

using namespace nlohmann;

PicoMQTT::Client mqtt;
bool mqtt_enabled = false;
mqttTopics_t mqtt_topics;

#ifdef PN532_USES_SPI
#include <SPI.h>
#include <PN532_SPI.h>
PN532_SPI pn532spi(SPI, PN532_SS);
PN532 nfc(pn532spi);
#else
#include <PN532_I2C.h>
PN532_I2C pn532i2c(Wire);
PN532 nfc(pn532i2c);
#endif

nvs_handle savedData;
homeKeyReader::readerData_t readerData;
bool defaultToStd = false;

#ifdef RELAY_PIN
#define RELAY_PIN_SEL (1ULL << RELAY_PIN)
static TickType_t next = 0;
const TickType_t period = RELAY_PERIOD / portTICK_PERIOD_MS;

static void close_relay(void *arg) {
    TickType_t now = xTaskGetTickCount();
    if ( now > next ) {
        gpio_set_level(RELAY_PIN, 1);
    }
    next = now + period;
}

static void open_relay(void *arg) {
    while ( true ) {
        TickType_t now = xTaskGetTickCount();
        if ( now > next ) {
            gpio_set_level(RELAY_PIN, 0);
            vTaskDelay(period);
        } else {
            vTaskDelay(next - now);
        }
    }
}
#endif // RELAY_PIN

bool save_to_nvs()
{
  const char *TAG = "save_to_nvs";
  json serializedData = readerData;
  auto msgpack = json::to_msgpack(serializedData);
  esp_err_t set_nvs = nvs_set_blob(savedData, "READERDATA", msgpack.data(), msgpack.size());
  ESP_LOGV(TAG, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
  if ( set_nvs != ESP_OK ) {
      ESP_LOGE(TAG, "Failed to set blob");
      return false;
  }
  esp_err_t commit_nvs = nvs_commit(savedData);
  ESP_LOGV(TAG, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
  return commit_nvs == ESP_OK;
}

struct LockManagement : Service::LockManagement
{
  SpanCharacteristic *lockControlPoint;
  SpanCharacteristic *version;
  const char *TAG = "LockManagement";

  LockManagement() : Service::LockManagement()
  {
    ESP_LOGI(TAG, "Configuring LockManagement"); // initialization message
    new Characteristic::Name("Lock Management");

    lockControlPoint = new Characteristic::LockControlPoint();
    version = new Characteristic::Version();
  } // end constructor

}; // end LockManagement

struct LockMechanism : Service::LockMechanism
{
  SpanCharacteristic *lockCurrentState;
  SpanCharacteristic *lockTargetState;
  const char *TAG = "LockMechanism";

  LockMechanism() : Service::LockMechanism()
  {
    ESP_LOGI(TAG, "Configuring LockMechanism"); // initialization message
    new Characteristic::Name("NFC Lock");
    lockCurrentState = new Characteristic::LockCurrentState(1, true);
    lockTargetState = new Characteristic::LockTargetState(1, true);
    if ( mqtt_enabled ) {
        if ( mqtt_topics.set_state_topic != nullptr ) {
            mqtt.subscribe(
                    mqtt_topics.set_state_topic, [this](const char *payload) {
                        ESP_LOGD(TAG, "Received message in topic set_state: %s", payload);
                        int state = atoi(payload);
                        lockTargetState->setVal(state == 0 || state == 1 ? state : lockTargetState->getVal());
                        lockCurrentState->setVal(state == 0 || state == 1 ? state : lockCurrentState->getVal());
                    },
                    false);
        }
        if ( mqtt_topics.set_target_topic != nullptr ) {
            mqtt.subscribe(
                    mqtt_topics.set_target_topic, [this](const char *payload) {
                        ESP_LOGD(TAG, "Received message in topic set_target_state: %s", payload);
                        int state = atoi(payload);
                        lockTargetState->setVal(state == 0 || state == 1 ? state : lockTargetState->getVal());
                    },
                    false);
        }
        if ( mqtt_topics.set_current_topic != nullptr ) {
            mqtt.subscribe(
                    mqtt_topics.set_current_topic, [this](const char *payload) {
                        ESP_LOGD(TAG, "Received message in topic set_current_state: %s", payload);
                        int state = atoi(payload);
                        lockCurrentState->setVal(state == 0 || state == 1 ? state : lockCurrentState->getVal());
                    },
                    false);
        }
    }
  } // end constructor

  boolean update(std::vector<char> *callback, int *callbackLen) override
  {
    int targetState = lockTargetState->getNewVal();
    ESP_LOGI(TAG, "New LockState=%d, Current LockState=%d", targetState, lockCurrentState->getVal());

    // lockCurrentState->setVal(targetState);
    if ( mqtt_enabled && mqtt_topics.state_topic != nullptr ) {
        mqtt.publish(mqtt_topics.state_topic, std::to_string(targetState).c_str());
    }

    return (true);
  }

  void loop() override
  {
    uint8_t uid[16];
    uint8_t uidLen = 0;
    uint16_t atqa[1];
    uint8_t sak[1];
    bool passiveTarget = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, atqa, sak, 1000, true);
    if (passiveTarget)
    {
      ESP_LOGI(TAG, "*** PASSIVE TARGET DETECTED ***");
      ESP_LOGD(TAG, "ATQA: %s SAK: %s UID: %s",
               utils::bufToHexString(atqa, 1).c_str(),
               utils::bufToHexString(sak, 1).c_str(),
               utils::bufToHexString(uid, uidLen).c_str()
      );

      // TODO: remove this filter? If we can't select the homekey applet next it's not a HomeKey?
      if (sak[0] == 0x20 && atqa[0] == 0x04)
      {
        unsigned long startTime = millis();
        uint8_t data[13] = {0x00, 0xA4, 0x04, 0x00, 0x07,
                            0xA0, 0x00, 0x00, 0x08, 0x58, 0x01, 0x01,
                            0x0};
        ESP_LOGD(TAG, "SELECT HomeKey Applet, APDU: %s", utils::bufToHexString(data, sizeof(data)).c_str());
        uint8_t selectCmdRes[32];
        uint8_t selectCmdResLength = 32;
        bool exchange = nfc.inDataExchange(data, sizeof(data), selectCmdRes, &selectCmdResLength);
        ESP_LOGD(TAG, "SELECT HomeKey Applet, Response: %s, Length: %d", utils::bufToHexString(selectCmdRes, selectCmdResLength).c_str(), selectCmdResLength);
        if (exchange)
        {
          if (selectCmdRes[selectCmdResLength - 2] == 0x90 && selectCmdRes[selectCmdResLength - 1] == 0x00)
          {
            ESP_LOGI(TAG, "*** SELECT HOMEKEY APPLET SUCCESSFUL ***");
            ESP_LOGD(TAG, "Reader Private Key: %s",
                     utils::bufToHexString((const uint8_t *)readerData.reader_private_key, sizeof(readerData.reader_private_key)).c_str());

            HKAuthenticationContext authCtx(nfc, readerData);
            auto authResult = authCtx.authenticate(defaultToStd, savedData);
            if (std::get<2>(authResult) != homeKeyReader::kFlowFailed)
            {
                publish_lock_state();
                publish_auth(std::get<0>(authResult), std::get<1>(authResult));
                ESP_LOGI(TAG, "Total time: %lu ms", millis() - startTime);
            }
            else // failed flow
            {
                ESP_LOGI(TAG, "failed flow");
            }
          }
          else // applet select failed
          {
              // possible not a HomeKey device
              publish_passive(atqa, sak, uid, uidLen);
          }
        }
        bool deviceStillInField = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen);
        while (deviceStillInField)
        {
          nfc.inRelease();
          vTaskDelay(100 / portTICK_PERIOD_MS);
          deviceStillInField = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen);
        }
        //nfc.inRelease();
      }
      else // not a homekey?
      {
          ESP_LOGI(TAG, "Not a HomeKey?");
      }
    }
    else // no passiveTarget
    {
      // ECP frame
      uint8_t data[18] = {0x6A, 0x2, 0xCB, 0x2, 0x6, 0x2, 0x11, 0x0};
      memcpy(data + 8, readerData.reader_identifier, sizeof(readerData.reader_identifier));
      utils::crc16a(data, 16, data + 16);
      uint8_t response[64];
      uint8_t length = 64;
      nfc.writeRegister(0x633d, 0);
      nfc.inCommunicateThru(data, sizeof(data), response, &length, 100);
    }
  } // end loop

  void publish_lock_state() const {
      int newTargetState = lockTargetState->getNewVal();
      int targetState = lockTargetState->getVal();
      // lockTargetState->setVal(!lockCurrentState->getVal());
      // lockCurrentState->setVal(lockTargetState->getVal());

      if ( mqtt_enabled && mqtt_topics.state_topic != nullptr ) {
          mqtt.publish(mqtt_topics.state_topic, std::to_string(newTargetState == targetState ? !lockCurrentState->getVal() : newTargetState).c_str());
      }
#ifdef RELAY_PIN
      // TODO: needs review
      close_relay(nullptr);
#endif
  }

  static void publish_passive(uint16_t *atqa, uint8_t *sak, uint8_t *uid, uint8_t uidLen) {
      json payload;
      payload["atqa"] = utils::bufToHexString(atqa, 1);
      payload["sak"] = utils::bufToHexString(sak, 1);
      payload["uid"] = utils::bufToHexString(uid, uidLen);
      payload["homekey"] = false;
      if ( mqtt_enabled && mqtt_topics.auth_topic != nullptr ) {
          mqtt.publish(mqtt_topics.auth_topic, payload.dump().c_str());
      }
  }

  static void publish_auth(uint8_t *issuerId, uint8_t *endpointId) {
      json payload;
      payload["issuerId"] = utils::bufToHexString(issuerId, 8);
      payload["endpointId"] = utils::bufToHexString(endpointId, 6);
      payload["homekey"] = true;
      if ( mqtt_enabled && mqtt_topics.auth_topic != nullptr ) {
          mqtt.publish(mqtt_topics.auth_topic, payload.dump().c_str());
      }
  }
}; // end LockMechanism

struct NFCAccess : Service::NFCAccess, CommonCryptoUtils
{
  SpanCharacteristic *configurationState;
  SpanCharacteristic *nfcControlPoint;
  SpanCharacteristic *nfcSupportedConfiguration;
  const char *TAG = "NFCAccess";

  NFCAccess() : Service::NFCAccess()
  {
    ESP_LOGI(TAG, "Configuring NFCAccess"); // initialization message
    new Characteristic::Name("NFC Access");
    configurationState = new Characteristic::ConfigurationState();
    nfcControlPoint = new Characteristic::NFCAccessControlPoint();
    nfcSupportedConfiguration = new Characteristic::NFCAccessSupportedConfiguration();
  } // end constructor

  std::tuple<uint8_t *, int> provision_device_cred(uint8_t *buf, size_t len)
  {
    for (size_t i = 0; i < 16; i++)
    {
      if (HAPClient::controllers[i].allocated)
      {
        std::vector<uint8_t> id = utils::getHashIdentifier(HAPClient::controllers[i].LTPK, 32, true);
        ESP_LOGD(TAG, "Found allocated controller - ID: %s", utils::bufToHexString(id.data(), 8).c_str());
        homeKeyIssuer::issuer_t *foundIssuer = nullptr;
        for (auto &issuer : readerData.issuers)
        {
          if (!memcmp(issuer.issuerId, id.data(), 8))
          {
            ESP_LOGD(TAG, "Issuer %s already added, skipping", utils::bufToHexString(issuer.issuerId, 8).c_str());
            foundIssuer = &issuer;
            break;
          }
        }
        if (foundIssuer == nullptr)
        {
          ESP_LOGD(TAG, "Adding new issuer - ID: %s", utils::bufToHexString(id.data(), 8).c_str());
          homeKeyIssuer::issuer_t issuer;
          memcpy(issuer.issuerId, id.data(), 8);
          memcpy(issuer.publicKey, HAPClient::controllers[i].LTPK, 32);
          readerData.issuers.emplace_back(issuer);
        }
      }
    }
    TLV<Device_Credential_Request, 5> tlv8;
    ESP_LOGD(TAG, "DCR Buffer length: %d, data: %s", len, utils::bufToHexString(buf, len).c_str());
    tlv8.create(kDevice_Req_Key_Type, 1, "KEY.TYPE");
    tlv8.create(kDevice_Req_Public_Key, 65, "PUBLIC.KEY");
    tlv8.create(kDevice_Req_Issuer_Key_Identifier, 8, "ISSUER.IDENTIFIER");
    tlv8.create(kDevice_Req_Key_State, 1, "KEY.STATE");
    tlv8.create(kDevice_Req_Key_Identifier, 8, "KEY.IDENTIFIER");

    ESP_LOGV(TAG, "DCR TLV DECODE STATE: %d", tlv8.unpack(buf, len));
    tlv8.print(1);
    homeKeyIssuer::issuer_t *foundIssuer = nullptr;
    for (auto &issuer : readerData.issuers)
    {
      if (!memcmp(issuer.issuerId, tlv8.buf(kDevice_Req_Issuer_Key_Identifier), 8))
      {
        ESP_LOGD(TAG, "Found issuer - ID: %s", utils::bufToHexString(issuer.issuerId, 8).c_str());
        foundIssuer = &issuer;
      }
    }
    if (foundIssuer != nullptr)
    {
      homeKeyEndpoint::endpoint_t *foundEndpoint = nullptr;
      uint8_t endEphPubKey[tlv8.len(kDevice_Req_Public_Key) + 1] = {0x04};
      memcpy(endEphPubKey + 1, tlv8.buf(kDevice_Req_Public_Key), tlv8.len(kDevice_Req_Public_Key));
      std::vector<uint8_t> endpointId = utils::getHashIdentifier(endEphPubKey, sizeof(endEphPubKey), false);
      for (auto &endpoint : foundIssuer->endpoints)
      {
        if (!memcmp(endpoint.endpointId, endpointId.data(), 6))
        {
          ESP_LOGD(TAG, "Found endpoint - ID: %s", utils::bufToHexString(endpoint.endpointId, 6).c_str());
          foundEndpoint = &endpoint;
        }
      }
      if (foundEndpoint == nullptr)
      {
        ESP_LOGD(TAG, "Adding new endpoint - ID: %s , PublicKey: %s", utils::bufToHexString(endpointId.data(), 6).c_str(), utils::bufToHexString(endEphPubKey, sizeof(endEphPubKey)).c_str());
        homeKeyEndpoint::endpoint_t endpoint;
        endpointEnrollment::enrollment_t enrollment;
        enrollment.unixTime = std::time(nullptr);
        uint8_t encoded[128];
        size_t olen = 0;
        mbedtls_base64_encode(encoded, 128, &olen, buf, len);
        enrollment.payload.insert(enrollment.payload.begin(), encoded, encoded + olen);
        std::vector<uint8_t> x_coordinate = get_x(endEphPubKey, sizeof(endEphPubKey));

        endpoint.counter = 0;
        endpoint.key_type = tlv8.buf(kDevice_Req_Key_Type)[0];
        endpoint.last_used_at = 0;
        endpoint.enrollments.hap = enrollment;
        std::fill(endpoint.persistent_key, endpoint.persistent_key + 32, 0);
        memcpy(endpoint.endpointId, endpointId.data(), 6);
        memcpy(endpoint.publicKey, endEphPubKey, sizeof(endEphPubKey));
        memcpy(endpoint.endpoint_key_x, x_coordinate.data(), x_coordinate.size());
        foundIssuer->endpoints.emplace_back(endpoint);
        save_to_nvs();
        return std::make_tuple(foundIssuer->issuerId, homeKeyReader::SUCCESS);
      }
      else
      {
        ESP_LOGD(TAG, "Endpoint already exists - ID: %s", utils::bufToHexString(foundEndpoint->endpointId, 6).c_str());
        save_to_nvs();
        return std::make_tuple(foundEndpoint->endpointId, homeKeyReader::DUPLICATE);
      }
      tlv8.clear();
    }
    else
    {
      ESP_LOGD(TAG, "Issuer does not exist - ID: %s", utils::bufToHexString(tlv8.buf(kDevice_Req_Issuer_Key_Identifier), 8).c_str());
      save_to_nvs();
      return std::make_tuple(tlv8.buf(kDevice_Req_Issuer_Key_Identifier), homeKeyReader::DOES_NOT_EXIST);
    }
    return std::make_tuple(readerData.reader_identifier, homeKeyReader::DOES_NOT_EXIST);
  }

  int set_reader_key(uint8_t *buf, size_t len)
  {
    ESP_LOGD(TAG, "Setting reader key: %s", utils::bufToHexString(buf, len).c_str());
    TLV<Reader_Key_Request, 3> tlv8;
    tlv8.create(kReader_Req_Key_Type, 1, "KEY.TYPE");
    tlv8.create(kReader_Req_Reader_Private_Key, 32, "READER.PRIV.KEY");
    tlv8.create(kReader_Req_Identifier, 8, "IDENTIFIER");
    // tlv8.create(kRequest_Reader_Key_Request, 64, "READER.REQ");
    // tlv8.create(kReader_Req_Key_Identifier, 64, "KEY.IDENTIFIER");

    ESP_LOGV(TAG, "RKR TLV DECODE STATE: %d", tlv8.unpack(buf, len));
    tlv8.print(1);
    uint8_t *readerKey = tlv8.buf(kReader_Req_Reader_Private_Key);
    uint8_t *uniqueIdentifier = tlv8.buf(kReader_Req_Identifier);
    ESP_LOGD(TAG, "Reader Key: %s", utils::bufToHexString(readerKey, tlv8.len(kReader_Req_Reader_Private_Key)).c_str());
    ESP_LOGD(TAG, "UniqueIdentifier: %s", utils::bufToHexString(uniqueIdentifier, tlv8.len(kReader_Req_Identifier)).c_str());
    std::vector<uint8_t> pubKey = getPublicKey(readerKey, tlv8.len(kReader_Req_Reader_Private_Key));
    ESP_LOGD(TAG, "Got reader public key: %s", utils::bufToHexString(pubKey.data(), pubKey.size()).c_str());
    std::vector<uint8_t> x_coordinate = get_x(pubKey.data(), pubKey.size());
    ESP_LOGD(TAG, "Got X coordinate: %s", utils::bufToHexString(x_coordinate.data(), x_coordinate.size()).c_str());
    memcpy(readerData.reader_key_x, x_coordinate.data(), x_coordinate.size());
    memcpy(readerData.reader_public_key, pubKey.data(), pubKey.size());
    // possible the two following return -1???
    memcpy(readerData.reader_private_key, readerKey, tlv8.len(kReader_Req_Reader_Private_Key));
    memcpy(readerData.identifier, uniqueIdentifier, tlv8.len(kReader_Req_Identifier));
    std::vector<uint8_t> readeridentifier = utils::getHashIdentifier(readerData.reader_private_key, sizeof(readerData.reader_private_key), true);
    ESP_LOGD(TAG, "Reader GroupIdentifier: %s", utils::bufToHexString(readeridentifier.data(), 8).c_str());
    memcpy(readerData.reader_identifier, readeridentifier.data(), 8);
    bool nvs = save_to_nvs();
    tlv8.clear();
    if (nvs)
    {
      return 0;
    }
    else
      return 1;
  }

  boolean update(std::vector<char> *callback, int *callbackLen) override
  {
    ESP_LOGD(TAG, "PROVISIONED READER KEY: %s", utils::bufToHexString(readerData.reader_private_key, sizeof(readerData.reader_private_key)).c_str());
    ESP_LOGD(TAG, "READER GROUP IDENTIFIER: %s", utils::bufToHexString(readerData.reader_identifier, sizeof(readerData.reader_identifier)).c_str());
    ESP_LOGD(TAG, "READER UNIQUE IDENTIFIER: %s", utils::bufToHexString(readerData.identifier, sizeof(readerData.identifier)).c_str());

    char *dataConfState = configurationState->getNewString();
    char *dataNfcControlPoint = nfcControlPoint->getNewString();
    ESP_LOGD(TAG, "NfcControlPoint Length: %d", strlen(dataNfcControlPoint));
    std::vector<uint8_t> decB64 = utils::decodeB64(dataNfcControlPoint);
    if (decB64.empty())
      return false;
    ESP_LOGD(TAG, "Decoded data: %s", utils::bufToHexString(decB64.data(), decB64.size()).c_str());
    ESP_LOGD(TAG, "Decoded data length: %d", decB64.size());
    std::vector<BERTLV> tlv = BERTLV::unpack_array(decB64);
    BERTLV operation = BERTLV::findTag(kTLVType1_Operation, tlv);
    ESP_LOGD(TAG, "Request Operation: %d", operation.value[0]);
    BERTLV RKR = BERTLV::findTag(kTLVType1_Reader_Key_Request, tlv);
    BERTLV DCR = BERTLV::findTag(kTLVType1_Device_Credential_Request, tlv);
    if (operation.value[0] == 1)
    {
      if (!RKR.tag.empty())
      {
        ESP_LOGI(TAG, "GET READER KEY REQUEST");
        if (strlen((const char *)readerData.reader_private_key) > 0)
        {
          size_t out_len = 0;
          TLV<Reader_Key_Response, 2> readerKeyResTlv;
          readerKeyResTlv.create(kReader_Res_Key_Identifier, 8, "KEY.IDENTIFIER");
          memcpy(readerKeyResTlv.buf(kReader_Res_Key_Identifier, 8), readerData.reader_identifier, 8);
          int lenSubTlv = readerKeyResTlv.pack(nullptr);
          uint8_t subTlv[lenSubTlv];
          readerKeyResTlv.pack(subTlv);
          ESP_LOGD(TAG, "SUB-TLV LENGTH: %d, DATA: %s", lenSubTlv, utils::bufToHexString(subTlv, lenSubTlv).c_str());
          readerKeyResTlv.clear();
          readerKeyResTlv.create(kReader_Res_Reader_Key_Response, lenSubTlv, "READER.RESPONSE");
          memcpy(readerKeyResTlv.buf(kReader_Res_Reader_Key_Response, lenSubTlv), subTlv, lenSubTlv);
          int lenTlv = readerKeyResTlv.pack(nullptr);
          uint8_t tlv[lenTlv];
          readerKeyResTlv.pack(tlv);
          ESP_LOGD(TAG, "TLV LENGTH: %d, DATA: %s", lenTlv, utils::bufToHexString(tlv, lenTlv).c_str());
          mbedtls_base64_encode(nullptr, 0, &out_len, tlv, lenTlv);
          uint8_t resB64[out_len + 1];
          int ret = mbedtls_base64_encode(resB64, sizeof(resB64), &out_len, tlv, lenTlv);
          if ( ret != 0 ) {
            ESP_LOGW(TAG, "Failure in mbedtls_base64_encode (%i)", ret);
          }
          resB64[out_len] = '\0';
          ESP_LOGD(TAG, "B64 ENC STATUS: %d", ret);
          ESP_LOGI(TAG, "RESPONSE LENGTH: %d, DATA: %s", out_len, resB64);
          callback->insert(callback->end(), resB64, resB64 + sizeof(resB64));
        }
      }
    }
    else if (operation.value[0] == 2)
    {
      if (!RKR.tag.empty())
      {
        ESP_LOGI(TAG, "SET READER KEY REQUEST");
        int ret = set_reader_key(RKR.value.data(), RKR.value.size());
        if (ret == 0)
        {
          ESP_LOGI(TAG, "KEY SAVED TO NVS, COMPOSING RESPONSE");
          size_t out_len = 0;
          TLV<Reader_Key_Response, 2> readerKeyResTlv;
          readerKeyResTlv.create(kReader_Res_Status, 1, "STATUS");
          readerKeyResTlv.val(kReader_Res_Status, 0);
          int lenSubTlv = readerKeyResTlv.pack(nullptr);
          uint8_t subTlv[lenSubTlv];
          readerKeyResTlv.pack(subTlv);
          ESP_LOGD(TAG, "SUB-TLV LENGTH: %d, DATA: %s", lenSubTlv, utils::bufToHexString(subTlv, lenSubTlv).c_str());
          readerKeyResTlv.clear();
          readerKeyResTlv.create(kReader_Res_Reader_Key_Response, lenSubTlv, "READER.RESPONSE");
          memcpy(readerKeyResTlv.buf(kReader_Res_Reader_Key_Response, lenSubTlv), subTlv, lenSubTlv);
          int lenTlv = readerKeyResTlv.pack(nullptr);
          uint8_t tlv[lenTlv];
          readerKeyResTlv.pack(tlv);
          ESP_LOGD(TAG, "TLV LENGTH: %d, DATA: %s", lenTlv, utils::bufToHexString(tlv, lenTlv).c_str());
          mbedtls_base64_encode(nullptr, 0, &out_len, tlv, lenTlv);
          unsigned char resB64[out_len + 1];
          ret = mbedtls_base64_encode(resB64, out_len, &out_len, tlv, lenTlv);
          if ( ret != 0 ) {
              ESP_LOGW(TAG, "Failure in mbedtls_base64_encode (%i)", ret);
          }
          resB64[out_len] = '\0';
          ESP_LOGD(TAG, "B64 ENC STATUS: %d", ret);
          ESP_LOGI(TAG, "RESPONSE LENGTH: %d, DATA: %s", out_len, resB64);
          callback->insert(callback->end(), resB64, resB64 + sizeof(resB64));
        }
      }
      else if (!DCR.tag.empty())
      {
        ESP_LOGI(TAG, "PROVISION DEVICE CREDENTIAL REQUEST");
        std::tuple<uint8_t *, int> state = provision_device_cred(DCR.value.data(), DCR.value.size());
        if (std::get<1>(state) != 99 && std::get<0>(state) != nullptr)
        {
          size_t out_len = 0;
          TLV<Device_Credential_Response, 4> devCredResTlv;
          devCredResTlv.create(kDevice_Res_Key_Identifier, 8, "KEY.IDENTIFIER");
          devCredResTlv.create(kDevice_Res_Issuer_Key_Identifier, 8, "ISSUER.IDENTIFIER");
          devCredResTlv.create(kDevice_Res_Status, 1, "STATUS");
          memcpy(devCredResTlv.buf(kDevice_Res_Issuer_Key_Identifier, 8), std::get<0>(state), 8);
          devCredResTlv.val(kDevice_Res_Status, std::get<1>(state));
          int lenSubTlv = devCredResTlv.pack(nullptr);
          uint8_t subTlv[lenSubTlv];
          devCredResTlv.pack(subTlv);
          ESP_LOGD(TAG, "SUB-TLV LENGTH: %d, DATA: %s", lenSubTlv, utils::bufToHexString(subTlv, lenSubTlv).c_str());
          devCredResTlv.clear();
          devCredResTlv.print(1);
          devCredResTlv.create(kDevice_Credential_Response, lenSubTlv, "DEV.RESPONSE");
          memcpy(devCredResTlv.buf(kDevice_Credential_Response, lenSubTlv), subTlv, lenSubTlv);
          int lenTlv = devCredResTlv.pack(nullptr);
          uint8_t tlv[lenTlv];
          devCredResTlv.pack(tlv);
          ESP_LOGD(TAG, "TLV LENGTH: %d, DATA: %s", lenTlv, utils::bufToHexString(tlv, lenTlv).c_str());
          mbedtls_base64_encode(nullptr, 0, &out_len, tlv, lenTlv);
          unsigned char resB64[out_len + 1];
          int ret = mbedtls_base64_encode(resB64, out_len, &out_len, tlv, lenTlv);
          if ( ret != 0 ) {
            ESP_LOGW(TAG, "Failure in mbedtls_base64_encode (%i)", ret);
          }
          resB64[out_len] = '\0';
          ESP_LOGD(TAG, "B64 ENC STATUS: %d", ret);
          ESP_LOGI(TAG, "RESPONSE LENGTH: %d, DATA: %s", out_len, resB64);
          callback->insert(callback->end(), resB64, resB64 + sizeof(resB64));
        }
      }
    }
    else if (operation.value[0] == 3)
    {
      ESP_LOGI(TAG, "REMOVE READER KEY REQUEST");
      std::fill(readerData.reader_identifier, readerData.reader_identifier + 8, 0);
      std::fill(readerData.reader_private_key, readerData.reader_private_key + 32, 0);
      json serializedData = readerData;
      auto msgpack = json::to_msgpack(serializedData);
      esp_err_t set_nvs = nvs_set_blob(savedData, "READERDATA", msgpack.data(), msgpack.size());
      esp_err_t commit_nvs = nvs_commit(savedData);
      ESP_LOGD(TAG, "NVS SET: %s", esp_err_to_name(set_nvs));
      ESP_LOGD(TAG, "NVS COMMIT: %s", esp_err_to_name(commit_nvs));
      const char *res = "BwMCAQA=";
      size_t resLen = 9;
      ESP_LOGI(TAG, "RESPONSE LENGTH: %d, DATA: %s", resLen, res);
      callback->insert(callback->end(), res, res + resLen);
    }
    return true;
  }

}; // end NFCAccess

//////////////////////////////////////

// stolen from Span::checkConnect() so we generate our Home Assistant unique ID the same as the MDNS name
char *get_unique_id() {
    char id[18];                              // create string version of Accessory ID for MDNS broadcast
    memcpy(id,HAPClient::accessory.ID,17);    // copy ID bytes
    id[17]='\0';                              // add terminating null

    int nChars=snprintf(nullptr,0,"%.2s%.2s%.2s%.2s%.2s%.2s",id,id+3,id+6,id+9,id+12,id+15);

    char str_id[nChars+1];
    sprintf(str_id,"%.2s%.2s%.2s%.2s%.2s%.2s",id,id+3,id+6,id+9,id+12,id+15);

    return strdup(str_id);
}

void wifiCallback()
{
  const char *TAG = "wifiCallback";
  size_t len;
  mqttData_t data;

#ifdef MQTT_HOST
    if (nvs_get_blob(savedData, "MQTTDATA", nullptr, &len) == ESP_ERR_NVS_NOT_FOUND )
    {
        // TODO: should check the lengths of the data before we try to memcpy()
        memcpy(&data.mqtt_host, MQTT_HOST, sizeof(MQTT_HOST));
        data.mqtt_port = MQTT_PORT;
        memcpy(&data.mqtt_client_id, MQTT_CLIENTID, sizeof(MQTT_CLIENTID));
        memcpy(&data.mqtt_username, MQTT_USERNAME, sizeof(MQTT_USERNAME));
        memcpy(&data.mqtt_password, MQTT_PASSWORD, sizeof(MQTT_PASSWORD));
        ESP_LOGI(TAG, "Setting default mqtt to: %s@%s:%i", data.mqtt_username, data.mqtt_host, data.mqtt_port);

        esp_err_t ret = nvs_set_blob(savedData, "MQTTDATA", &data, sizeof(data));
        if ( ret != ESP_OK ) {
            ESP_LOGW(TAG, "Failed call to nvs_set_blob (%s)", esp_err_to_name(ret));
        }
        ret = nvs_commit(savedData);
        if ( ret != ESP_OK ) {
            ESP_LOGW(TAG, "Failed call to nvs_commit (%s)", esp_err_to_name(ret));
        }
    }
#endif
    if (nvs_get_blob(savedData, "MQTTDATA", nullptr, &len) == ESP_OK )
    {
        if ( len != sizeof(mqttData_t)) {
            // TODO
        }
        nvs_get_blob(savedData, "MQTTDATA", &data, &len);
        ESP_LOGI(TAG, "Found mqtt: %s@%s:%i", data.mqtt_username, data.mqtt_host, data.mqtt_port);
        mqtt.host = data.mqtt_host;
        mqtt.port = data.mqtt_port;
        mqtt.client_id = data.mqtt_client_id;
        mqtt.username = data.mqtt_username;
        mqtt.password = data.mqtt_password;

        char *unique_id = get_unique_id();
        asprintf(&mqtt_topics.prefix, MQTT_PREFIX, unique_id);
        // TODO: state topic is optional if we are only sending auth messages
        asprintf(&mqtt_topics.state_topic, MQTT_STATE_TOPIC, unique_id);
        ESP_LOGD(TAG, "State topic: %s", mqtt_topics.state_topic);
#ifdef MQTT_AUTH_TOPIC
        asprintf(&mqtt_topics.auth_topic, MQTT_AUTH_TOPIC, unique_id);
#endif
#ifdef MQTT_SET_STATE_TOPIC
        asprintf(&mqtt_topics.set_state_topic, MQTT_SET_STATE_TOPIC, unique_id);
#endif
#ifdef MQTT_SET_CURRENT_STATE_TOPIC
        asprintf(&mqtt_topics.set_current_topic, MQTT_SET_CURRENT_STATE_TOPIC, unique_id);
#endif
#ifdef MQTT_SET_TARGET_STATE_TOPIC
        asprintf(&mqtt_topics.set_target_topic, MQTT_SET_TARGET_STATE_TOPIC, unique_id);
#endif

#ifdef HA_DISCOVERY_PREFIX
        // set up a last will message on the broker
        mqtt.will.topic = mqtt_topics.prefix;
        mqtt.will.payload = "offline";
        mqtt.will.qos = 1;
        mqtt.will.retain = true;

        // set up a connection callback to update our availability topic
        mqtt.connected_callback = [] {
            mqtt.publish(mqtt_topics.prefix, "online");
        };
#endif

        mqtt.begin();
        mqtt_enabled = true;

#ifdef HA_DISCOVERY_PREFIX
        ESP_LOGI(TAG, "Enabling HomeAssistant discovery");

        // let mqtt get some time to make any needed connections to the broker
        mqtt.loop();

        // TODO: Lock control topic?
        // TODO: is this lock device valid if we are only sending auth messages?
        const char *config_json = R"END({
"name":null,
"dev_cla":"lock",
"stat_t":"%s",
"pl_on":"0",
"pl_off":"1",
"avty_t":"%s",
"pl_avail":"online",
"pl_not_avail":"offline",
"uniq_id":"state%s",
"dev":{
 "ids":["%s"],
 "name":"%s",
 "sw":"%s"
}
})END";

        char *message;
        asprintf(&message, config_json,
                 mqtt_topics.state_topic, mqtt_topics.prefix,
                 unique_id, unique_id,
                 DISPLAY_NAME, __DATE__ " " __TIME__);
        char *topic;
        asprintf(&topic, "%s/binary_sensor/%s/config", HA_DISCOVERY_PREFIX, unique_id);
        ESP_LOGD(TAG, "topic: %s", topic);
        ESP_LOGD(TAG, "message: %s", message);
        mqtt.publish(topic, message, 0, true);
        free(message);
        free(topic);
#endif
        free(unique_id);
    }
}

void setup()
{
  Serial.begin(115200);
  size_t len;
  const char *TAG = "SETUP";

#ifdef RELAY_PIN
  gpio_config_t relay_conf;
  relay_conf.mode = GPIO_MODE_OUTPUT;
  relay_conf.pin_bit_mask = RELAY_PIN_SEL;
  relay_conf.intr_type = GPIO_INTR_DISABLE;
  relay_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
  relay_conf.pull_up_en = GPIO_PULLUP_DISABLE;
  gpio_config(&relay_conf);

  xTaskCreate(open_relay, "openrly", configMINIMAL_STACK_SIZE, nullptr, 5, nullptr);
#endif

  nvs_open("SAVED_DATA", NVS_READWRITE, &savedData);
  if (nvs_get_blob(savedData, "READERDATA", nullptr, &len) == ESP_OK )
  {
    uint8_t msgpack[len];
    nvs_get_blob(savedData, "READERDATA", msgpack, &len);
    ESP_LOGV(TAG, "READERDATA - MSGPACK(%d): %s", len, utils::bufToHexString(msgpack, len).c_str());
    json data = json::from_msgpack(msgpack, msgpack + len);
    ESP_LOGD(TAG, "READERDATA - JSON(%d): %s", len, data.dump(-1).c_str());
    homeKeyReader::readerData_t p = data.template get<homeKeyReader::readerData_t>();
    readerData = p;
  }
  homeSpan.setStatusPin(GPIO_NUM_2);
  // homeSpan.setStatusAutoOff(5);
  homeSpan.reserveSocketConnections(2);
  homeSpan.setLogLevel(0);

  ESP_LOGD(TAG, "READER GROUP ID (%d): %s", strlen((const char *)readerData.reader_identifier), utils::bufToHexString(readerData.reader_identifier, sizeof(readerData.reader_identifier)).c_str());
  ESP_LOGD(TAG, "READER UNIQUE ID (%d): %s", strlen((const char *)readerData.identifier), utils::bufToHexString(readerData.identifier, sizeof(readerData.identifier)).c_str());

  ESP_LOGI(TAG, "HOMEKEY ISSUERS: %d", readerData.issuers.size());
  for (auto &issuer : readerData.issuers)
  {
    ESP_LOGD(TAG, "Issuer ID: %s, Public Key: %s", utils::bufToHexString(issuer.issuerId, sizeof(issuer.issuerId)).c_str(), utils::bufToHexString(issuer.publicKey, sizeof(issuer.publicKey)).c_str());
  }
#ifdef HOSTNAME_SUFFIX
  homeSpan.setHostNameSuffix(HOSTNAME_SUFFIX);
#endif
#ifdef OTA_AUTH
    nvs_handle otaNVS;
    // see HomeSpan.cpp for specifics on this NVS data
    nvs_open("OTA",NVS_READONLY,&otaNVS);
    if ( nvs_get_str(otaNVS, "OTADATA", nullptr, &len) == ESP_ERR_NOT_FOUND ) {
        // no OTA password set in NVS so use the compile time default
        ESP_LOGD(TAG, "Using compile-time OTA password");
        homeSpan.enableOTA(OTA_AUTH);
    } else {
        // looks like there is an OTA password set in NVS so we'll let OTA use that
        homeSpan.enableOTA();
    }
    nvs_close(otaNVS);
#endif
  homeSpan.begin(Category::Locks, DISPLAY_NAME);
#ifdef WIFI_SSID
  homeSpan.setWifiCredentials(WIFI_SSID, WIFI_CREDENTIALS);
#else
  homeSpan.enableAutoStartAP();
#endif
#ifdef PAIRING_CODE
  homeSpan.setPairingCode(PAIRING_CODE);
#endif
  homeSpan.setSerialInputDisable(DISABLE_SERIAL_PORT);
  homeSpan.setSketchVersion(__DATE__ " " __TIME__);

  new SpanUserCommand('D', "Delete Home Key Data", deleteReaderData);
  new SpanUserCommand('L', "Set Log Level", setLogLevel);
  new SpanUserCommand('F', "Set HomeKey Flow", setFlow);
  new SpanUserCommand('I', "Add dummy Issuers and endpoints", insertDummyIssuers);
  new SpanUserCommand('P', "Print Issuers", printIssuers);
  new SpanUserCommand('M', "Set MQTT Configuration", setMqttConfiguration);
  // TODO: print MQTT configuration command
  // TODO: move topic configuration to NVS
  // TODO: move HA configuration to NVS

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata)
  {
    ESP_LOGE("NFC_SETUP", "Didn't find PN53x board");
  }
  else
  {
    ESP_LOGI("NFC_SETUP", "Found chip PN5%x", (versiondata >> 24) & 0xFF);
    ESP_LOGI("NFC_SETUP", "Firmware ver. %d.%d", (versiondata >> 16) & 0xFF, (versiondata >> 8) & 0xFF);
    nfc.SAMConfig();
    nfc.setPassiveActivationRetries(0);
    ESP_LOGI("NFC_SETUP", "Waiting for an ISO14443A card");
  }

  new SpanAccessory();                 // Begin by creating a new Accessory using SpanAccessory(), no arguments needed
  new Service::AccessoryInformation(); // HAP requires every Accessory to implement an AccessoryInformation Service, with the required Identify Characteristic
  new Characteristic::Identify();
  new Characteristic::Manufacturer();
  new Characteristic::Model();
  new Characteristic::Name("NFC Lock");
  new Characteristic::SerialNumber();
  new Characteristic::FirmwareRevision();
  new Characteristic::HardwareFinish(HARDWARE_FINISH);

  new LockManagement();
  new LockMechanism();
  new NFCAccess();
  new Service::HAPProtocolInformation();
  new Characteristic::Version();
  homeSpan.setPairCallback(pairCallback);
  homeSpan.setWifiCallback(wifiCallback);
}

//////////////////////////////////////

void loop()
{
  homeSpan.poll();
  mqtt.loop();
}
