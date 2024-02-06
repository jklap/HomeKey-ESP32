#include <auth/authContext.h>

#define LOG(x, format, ...) ESP_LOG##x(TAG, "%s > " format , __FUNCTION__ __VA_OPT__(,) __VA_ARGS__)

/**
 * The function performs an elliptic curve Diffie-Hellman key exchange to compute a shared key between
 * the reader and the endpoint.
 * 
 * @param outBuf The `outBuf` parameter is a pointer to a buffer where the computed shared key will be
 * stored. It should be allocated with enough space to hold `oLen` bytes.
 * @param oLen oLen is the length of the output buffer (outBuf) where the shared key will be written.
 */
void HKAuthenticationContext::get_shared_key(uint8_t *outBuf, size_t oLen)
{
  mbedtls_ecp_group grp;
  mbedtls_mpi reader_ephemeral_private_key, shared_key;
  mbedtls_ecp_point endpoint_ephemeral_public_key;

  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&reader_ephemeral_private_key);
  mbedtls_mpi_init(&shared_key);
  mbedtls_ecp_point_init(&endpoint_ephemeral_public_key);

  // Initialize the elliptic curve group (e.g., SECP256R1)
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  // Set the reader's ephemeral private key
  int mpi_read = mbedtls_mpi_read_binary(&reader_ephemeral_private_key, readerEphPrivKey.data(), readerEphPrivKey.size());
  if(mpi_read != 0){
    ESP_LOGE(TAG, "get_shared_key > mpi_read - %s: %s", mbedtls_high_level_strerr(mpi_read), mbedtls_low_level_strerr(mpi_read));
    return;
  }

  // Set the endpoint's ephemeral public key
  int ecp_read = mbedtls_ecp_point_read_binary(&grp, &endpoint_ephemeral_public_key, endpointEphPubKey.data(), endpointEphPubKey.size());
  if(ecp_read != 0){
    ESP_LOGE(TAG, "get_shared_key > ecp_read - %s: %s", mbedtls_high_level_strerr(ecp_read), mbedtls_low_level_strerr(ecp_read));
    return;
  }

  // Perform key exchange
  int ecdh_compute_shared = mbedtls_ecdh_compute_shared(&grp, &shared_key, &endpoint_ephemeral_public_key, &reader_ephemeral_private_key,
                                                        esp_rng, nullptr);
  if(ecdh_compute_shared != 0){
    ESP_LOGE(TAG, "get_shared_key > ecdh_compute_shared - %s: %s", mbedtls_high_level_strerr(ecdh_compute_shared), mbedtls_low_level_strerr(ecdh_compute_shared));
    return;
  }

  int mpi_write = mbedtls_mpi_write_binary(&shared_key, outBuf, oLen);
  if(mpi_write != 0){
    ESP_LOGE(TAG, "get_shared_key > mpi_write - %s: %s", mbedtls_high_level_strerr(mpi_write), mbedtls_low_level_strerr(mpi_write));
    return;
  }

  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&reader_ephemeral_private_key);
  mbedtls_mpi_free(&shared_key);
  mbedtls_ecp_point_free(&endpoint_ephemeral_public_key);
}

 /**
   * The function `AuthenticationContext::AuthenticationContext` initializes the AuthenticationContext
   * object by generating an ephemeral key, filling the transaction identifier with random data, and
   * copying reader identifiers.
   *
   * @param nfc A pointer to an instance of the PN532 class, which is used for NFC communication.
   * @param readerData readerData is a pointer to a structure of type readerData_t.
   */
 HKAuthenticationContext::HKAuthenticationContext(PN532 &nfc, homeKeyReader::readerData_t &readerData) : readerData(readerData), nfc(nfc)
 {
  auto startTime = std::chrono::high_resolution_clock::now();
  auto readerEphKey = generateEphemeralKey();
  readerEphPrivKey = std::move(std::get<0>(readerEphKey));
  readerEphPubKey = std::move(std::get<1>(readerEphKey));
  transactionIdentifier.resize(16);
  transactionIdentifier.reserve(16);
  esp_fill_random(transactionIdentifier.data(), 16);
  readerIdentifier.reserve(sizeof(readerData.reader_identifier) + sizeof(readerData.identifier));
  readerIdentifier.insert(readerIdentifier.begin(), readerData.reader_identifier, readerData.reader_identifier + sizeof(readerData.reader_identifier));
  readerIdentifier.insert(readerIdentifier.end(), readerData.identifier, readerData.identifier + sizeof(readerData.identifier));
  readerEphX = std::move(get_x(readerEphPubKey));
  auto stopTime = std::chrono::high_resolution_clock::now();
  LOG(I, "Initialization Time: %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
}

std::tuple<uint8_t *, uint8_t *, homeKeyReader::KeyFlow> HKAuthenticationContext::authenticate(bool defaultToStd, nvs_handle &savedData){
    auto startTime = std::chrono::high_resolution_clock::now();
    auto fastAuth = fast_auth(defaultToStd);
    homeKeyIssuer::issuer_t *foundIssuer = nullptr;
    homeKeyEndpoint::endpoint_t *foundEndpoint = nullptr;
    if (std::get<1>(fastAuth) != nullptr && std::get<2>(fastAuth) != homeKeyReader::kFlowFailed)
    {
        foundIssuer = std::get<0>(fastAuth);
        foundEndpoint = std::get<1>(fastAuth);
        auto stopTime = std::chrono::high_resolution_clock::now();
        LOG(I, "Home Key authenticated, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
        nfc.inRelease();
        return std::make_tuple(foundIssuer->issuerId, foundEndpoint->endpointId, homeKeyReader::kFlowFAST);
    }
    else if (std::get<2>(fastAuth) == homeKeyReader::kFlowSTANDARD)
    {
        auto stdAuth = std_auth();
        foundIssuer = std::get<0>(stdAuth);
        foundEndpoint = std::get<1>(stdAuth);
        if (foundEndpoint != nullptr && std::get<4>(stdAuth) == homeKeyReader::kFlowSTANDARD)
        {
            auto stopTime = std::chrono::high_resolution_clock::now();
            LOG(I, "Home Key authenticated, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
            std::vector<uint8_t> persistentKey = std::get<3>(stdAuth);
            memcpy(foundEndpoint->persistent_key, persistentKey.data(), 32);
            json serializedData = readerData;
            auto msgpack = json::to_msgpack(serializedData);
            esp_err_t set_nvs = nvs_set_blob(savedData, "READERDATA", msgpack.data(), msgpack.size());
            esp_err_t commit_nvs = nvs_commit(savedData);
            ESP_LOGV(TAG, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
            ESP_LOGV(TAG, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
            nfc.inRelease();
            return std::make_tuple(foundIssuer->issuerId, foundEndpoint->endpointId, homeKeyReader::kFlowSTANDARD);
        }
    }
    nfc.inRelease();
    return std::make_tuple(foundIssuer->issuerId, foundEndpoint->endpointId, homeKeyReader::kFlowFailed);
}


/**
 * The function `Auth0_keying_material` generates keying material using the HKDF algorithm based on
 * various input parameters.
 *
 * @param context The `context` parameter is a pointer to a character array that represents the context
 * for the keying material generation. It is used as input to the HKDF (HMAC-based Key Derivation
 * Function) algorithm.
 * @param ePub_X ePub_X is a pointer to a uint8_t array that represents the public key of the entity
 * being authenticated. It has a length of 32 bytes.
 * @param keyingMaterial The `keyingMaterial` parameter is a pointer to a buffer where the input keying material to be used with HKDF is stored.
 * It should have a size of at least 32 bytes.
 * @param out The `out` parameter is a pointer to the buffer where the output keying material will be
 * stored. The size of the buffer is specified by the `outLen` parameter.
 * @param outLen The parameter `outLen` represents the length of the output buffer `out`. It specifies
 * the maximum number of bytes that can be written to the `out` buffer.
 */
void HKAuthenticationContext::Auth0_keying_material(const char *context, const uint8_t *ePub_X, const uint8_t *keyingMaterial, uint8_t *out, size_t outLen)
{
  uint8_t interface = 0x5E;
  uint8_t flags[2] = {0x01, 0x01};
  uint8_t prot_ver[4] = {0x5c, 0x02, 0x02, 0x0};
  uint8_t supported_vers[6] = {0x5c, 0x04, 0x02, 0x0, 0x01, 0x0};
  uint8_t dataMaterial[32 + strlen(context) + readerIdentifier.size() + 32 + 1 + sizeof(supported_vers) + sizeof(prot_ver) + readerEphX.size() + 16 + 2 + endpointEphX.size()];
  size_t olen = 0;
  utils::pack(readerData.reader_key_x, 32, dataMaterial, &olen);
  utils::pack((uint8_t *)context, strlen(context), dataMaterial, &olen);
  utils::pack(readerIdentifier.data(), readerIdentifier.size(), dataMaterial, &olen);
  utils::pack(ePub_X, 32, dataMaterial, &olen);
  utils::pack(&interface, 1, dataMaterial, &olen);
  utils::pack(supported_vers, sizeof(supported_vers), dataMaterial, &olen);
  utils::pack(prot_ver, sizeof(prot_ver), dataMaterial, &olen);
  utils::pack(readerEphX.data(), readerEphX.size(), dataMaterial, &olen);
  utils::pack(transactionIdentifier.data(), 16, dataMaterial, &olen);
  utils::pack(flags, 2, dataMaterial, &olen);
  utils::pack(endpointEphX.data(), endpointEphX.size(), dataMaterial, &olen);
  ESP_LOGD(TAG, "Auth0 HKDF Material: %s", utils::bufToHexString(dataMaterial, sizeof(dataMaterial)).c_str());
  int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), nullptr, 0, keyingMaterial, 32, dataMaterial, sizeof(dataMaterial), out, outLen);
  ESP_LOGV(TAG, "HKDF Status: %d", ret);
}

/**
 * The function `Auth1_keying_material` generates keying material using various input data and the HKDF
 * algorithm.
 * 
 * @param keyingMaterial A pointer to the buffer where the generated keying material will be stored.
 * @param context The "context" parameter is a string that represents the context or additional
 * information for the authentication process. It is used as input to generate the keying material.
 * @param out The `out` parameter is a pointer to a buffer where the generated keying material will be
 * stored. The size of this buffer is specified by the `outLen` parameter.
 * @param outLen The parameter `outLen` represents the length of the output buffer `out` where the
 * generated keying material will be stored.
 */
void HKAuthenticationContext::Auth1_keying_material(uint8_t *keyingMaterial, const char *context, uint8_t *out, size_t outLen)
{
  uint8_t interface = 0x5E;
  uint8_t flags[2] = {0x01, 0x01};
  uint8_t prot_ver[4] = {0x5c, 0x02, 0x02, 0x0};
  uint8_t supported_vers[6] = {0x5c, 0x04, 0x02, 0x0, 0x01, 0x0};
  uint8_t dataMaterial[readerEphX.size() + endpointEphX.size() + transactionIdentifier.size() + 1 + sizeof(flags) + strlen(context) + sizeof(prot_ver) + sizeof(supported_vers)];
  size_t olen = 0;
  utils::pack(readerEphX.data(), readerEphX.size(), dataMaterial, &olen);
  utils::pack(endpointEphX.data(), endpointEphX.size(), dataMaterial, &olen);
  utils::pack(transactionIdentifier.data(), 16, dataMaterial, &olen);
  utils::pack(&interface, 1, dataMaterial, &olen);
  utils::pack(flags, 2, dataMaterial, &olen);
  utils::pack((uint8_t *)context, strlen(context), dataMaterial, &olen);
  utils::pack(prot_ver, sizeof(prot_ver), dataMaterial, &olen);
  utils::pack(supported_vers, sizeof(supported_vers), dataMaterial, &olen);
  ESP_LOGD(TAG, "DATA Material Length: %d, Data: %s", sizeof(dataMaterial), utils::bufToHexString(dataMaterial, sizeof(dataMaterial)).c_str());
  mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), nullptr, 0, keyingMaterial, 32, dataMaterial, olen, out, outLen);
}

std::vector<uint8_t> HKAuthenticationContext::commandFlow(homeKeyReader::CommandFlowStatus status)
{
    uint8_t apdu[4] = {0x80, 0x3c, static_cast<uint8_t>(status), status == homeKeyReader::kCmdFlowAttestation ? (uint8_t)0xa0 : (uint8_t)0x0};
    std::vector<uint8_t> cmdFlowRes(4);
    uint8_t cmdFlowResLen = cmdFlowRes.size();
    ESP_LOGD(TAG, "APDU: %s, Length: %d", utils::bufToHexString(apdu, sizeof(apdu)).c_str(), sizeof(apdu));
    nfc.inDataExchange(apdu, sizeof(apdu), cmdFlowRes.data(), &cmdFlowResLen);
    return cmdFlowRes;
}

/**
 * The function `find_endpoint_by_cryptogram` searches for an endpoint in a list of issuers based on a
 * given cryptogram.
 * 
 * @param cryptogram The parameter "cryptogram" is a vector of uint8_t, which represents a cryptogram.
 * 
 * @return a pointer to an object of type `issuerEndpoint::issuerEndpoint_t`.
 */
std::tuple<homeKeyIssuer::issuer_t *, homeKeyEndpoint::endpoint_t *> HKAuthenticationContext::find_endpoint_by_cryptogram(std::vector<uint8_t> &cryptogram)
{
  homeKeyEndpoint::endpoint_t *foundEndpoint = nullptr;
  homeKeyIssuer::issuer_t *foundIssuer = nullptr;
  for (auto &&issuer : readerData.issuers)
  {
    ESP_LOGV(TAG, "Issuer: %s, Endpoints: %d", utils::bufToHexString(issuer.issuerId, sizeof(issuer.issuerId)).c_str(), issuer.endpoints.size());
    for (auto &&endpoint : issuer.endpoints)
    {
      ESP_LOGV(TAG, "Endpoint: %s, Persistent Key: %s", utils::bufToHexString(endpoint.endpointId, sizeof(endpoint.endpointId)).c_str(), utils::bufToHexString(endpoint.persistent_key, sizeof(endpoint.persistent_key)).c_str());
      uint8_t hkdf[58];
      Auth0_keying_material("VolatileFast", endpoint.endpoint_key_x, endpoint.persistent_key, hkdf, sizeof(hkdf));
      ESP_LOGD(TAG, "HKDF Derived Key: %s", utils::bufToHexString(hkdf, sizeof(hkdf)).c_str());
      if (!memcmp(hkdf, cryptogram.data(), 16))
      {
        ESP_LOGD(TAG, "Endpoint %s matches cryptogram", utils::bufToHexString(endpoint.endpointId, sizeof(endpoint.endpointId)).c_str());
        foundEndpoint = &endpoint;
        foundIssuer = &issuer;
        break;
      }
    }
    if (foundEndpoint != nullptr)
    {
      break;
    }
  }
  return std::make_tuple(foundIssuer, foundEndpoint);
}

/**
 * The function `Auth1_keys_generator` generates persistent and volatile keys using a shared key and
 * X963KDF algorithm.
 * 
 * @param persistentKey The `persistentKey` parameter is a pointer to a buffer where the generated
 * persistent key will be stored. It should have a size of at least 32 bytes.
 * @param volatileKey The `volatileKey` parameter is a pointer to a buffer that will store the volatile
 * key. It is expected to be an array of `uint8_t` with a size of 48 bytes.
 */
void HKAuthenticationContext::Auth1_keys_generator(uint8_t *persistentKey, uint8_t *volatileKey)
{
  uint8_t sharedKey[32];

  get_shared_key(sharedKey, sizeof(sharedKey));
  ESP_LOGD(TAG, "Shared Key: %s", utils::bufToHexString(sharedKey, 32).c_str());

  X963KDF kdf(MBEDTLS_MD_SHA256, 32, transactionIdentifier.data(), 16);

  // Derive the key using X963KDF
  uint8_t derivedKey[32];
  kdf.derive(sharedKey, sizeof(sharedKey), derivedKey);
  ESP_LOGD(TAG, "X963KDF Derived Key: %s", utils::bufToHexString(derivedKey, 32).c_str());
  Auth1_keying_material(derivedKey, "Persistent", persistentKey, 32);
  Auth1_keying_material(derivedKey, "Volatile", volatileKey, 48);
  ESP_LOGD(TAG, "Persistent Key: %s", utils::bufToHexString(persistentKey, 32).c_str());
  ESP_LOGD(TAG, "Volatile Key: %s", utils::bufToHexString(volatileKey, 48).c_str());
}


/**
 * The function `fast_auth` performs a fast authentication process and returns the endpoint and
 * authentication flow type.
 * 
 * @param fallbackToStd The `fallbackToStd` parameter is a boolean flag that indicates whether to
 * fallback to the standard authentication flow if the fast authentication flow fails. If
 * `fallbackToStd` is `true`, the function will return a tuple with `endpoint` set to `nullptr` and the
 * second value set to `
 * 
 * @return a std::tuple containing a pointer to an issuerEndpoint_t object and an integer value.
 */
std::tuple<homeKeyIssuer::issuer_t *, homeKeyEndpoint::endpoint_t *, homeKeyReader::KeyFlow> HKAuthenticationContext::fast_auth(bool fallbackToStd)
{
  uint8_t prot_v_data[2] = {0x02, 0x0};

  std::vector<uint8_t> fastTlv(sizeof(prot_v_data) + readerEphPubKey.size() + transactionIdentifier.size() + readerIdentifier.size() + 8);
  size_t len = 0;
  utils::simple_tlv(0x5C, prot_v_data, sizeof(prot_v_data), fastTlv.data(), &len);
  utils::simple_tlv(0x87, readerEphPubKey.data(), readerEphPubKey.size(), fastTlv.data() + len, &len);
  utils::simple_tlv(0x4C, transactionIdentifier.data(), transactionIdentifier.size(), fastTlv.data() + len, &len);
  utils::simple_tlv(0x4D, readerIdentifier.data(), readerIdentifier.size(), fastTlv.data() + len, &len);
  std::vector<uint8_t> apdu{0x80, 0x80, 0x01, 0x01, (uint8_t)len};
  apdu.insert(apdu.begin() + 5, fastTlv.begin(), fastTlv.end());

  uint8_t response[128];
  uint8_t responseLength = 128;
  ESP_LOGD(TAG, "Auth0 APDU Length: %d, DATA: %s", apdu.size(), utils::bufToHexString(apdu.data(), apdu.size()).c_str());
  nfc.inDataExchange(apdu.data(), apdu.size(), response, &responseLength);
  ESP_LOGD(TAG, "Auth0 Response Length: %d, DATA: %s", responseLength, utils::bufToHexString(response, responseLength).c_str());
  homeKeyIssuer::issuer_t *issuer = nullptr;
  homeKeyEndpoint::endpoint_t *endpoint = nullptr;
  if (response[responseLength - 2] == 0x90 && response[0] == 0x86)
  {
    auto Auth0Res = BERTLV::unpack_array(response, responseLength);
    auto endpointPubKey = BERTLV::findTag(kEndpoint_Public_Key, Auth0Res);
    endpointEphPubKey = std::move(endpointPubKey.value);
    auto encryptedMessage = BERTLV::findTag(kAuth0_Cryptogram, Auth0Res);
    endpointEphX = std::move(get_x(endpointEphPubKey));
    if (fallbackToStd)
    {
      return std::make_tuple(issuer, endpoint, homeKeyReader::kFlowSTANDARD);
    }
    else
    {
      auto foundData = find_endpoint_by_cryptogram(encryptedMessage.value);
      endpoint = std::get<1>(foundData);
      issuer = std::get<0>(foundData);

      if (endpoint != nullptr)
      {
        ESP_LOGI(TAG, "Endpoint %s Authenticated via FAST Flow", utils::bufToHexString(endpoint->endpointId, sizeof(endpoint->endpointId), true).c_str());
        std::vector<uint8_t> cmdFlowStatus = commandFlow(homeKeyReader::kCmdFlowSuccess);
        ESP_LOGD(TAG, "RESPONSE: %s, Length: %d", utils::bufToHexString(cmdFlowStatus.data(), cmdFlowStatus.size()).c_str(), cmdFlowStatus.size());
        if (cmdFlowStatus[0] == 0x90)
        {
          ESP_LOGI(TAG, "Command Status 0x90, FAST Flow Complete");
          return std::make_tuple(issuer, endpoint, homeKeyReader::kFlowFAST);
        }
      }
      else
      {
        ESP_LOGW(TAG, "FAST Flow failed!");
        return std::make_tuple(issuer, endpoint, homeKeyReader::kFlowSTANDARD);
      }
    }
  }
  ESP_LOGE(TAG, "Response not valid, something went wrong!");
  commandFlow(homeKeyReader::kCmdFlowFailed);
  return std::make_tuple(issuer, endpoint, homeKeyReader::kFlowFailed);
}

/**
 * The function `std_auth()` performs a standard authentication process using various cryptographic
 * operations and NFC communication.
 * 
 * @return a tuple containing four elements:
 * 1. A pointer to an object of type `issuerEndpoint::issuerEndpoint_t*`
 * 2. An object of type `DigitalKeySecureContext`
 * 3. A vector of type `std::vector<uint8_t>`
 * 4. An object of type `homeKeyReader::KeyFlow`
 */
std::tuple<homeKeyIssuer::issuer_t *, homeKeyEndpoint::endpoint_t *, DigitalKeySecureContext, std::vector<uint8_t>, homeKeyReader::KeyFlow> HKAuthenticationContext::std_auth()
{
  // int readerContext = 1096652137;
  uint8_t readerCtx[4]{0x41,0x5d,0x95,0x69};
  // int deviceContext = 1317567308;
  uint8_t deviceCtx[4]{0x4e,0x88,0x7b,0x4c};

  std::vector<uint8_t> stdTlv(16 + endpointEphX.size() + readerEphX.size() + 30);
  size_t len = 0;
  utils::simple_tlv(0x4D, readerIdentifier.data(), 16, stdTlv.data(), &len);
  utils::simple_tlv(0x86, endpointEphX.data(), endpointEphX.size(), stdTlv.data() + len, &len);
  utils::simple_tlv(0x87, readerEphX.data(), readerEphX.size(), stdTlv.data() + len, &len);
  utils::simple_tlv(0x4C, transactionIdentifier.data(), 16, stdTlv.data() + len, &len);
  utils::simple_tlv(0x93, readerCtx, 4, stdTlv.data() + len, &len);
  auto sigTlv = signSharedInfo(stdTlv.data(), len, readerData.reader_private_key, sizeof(readerData.reader_private_key));
  std::vector<uint8_t> apdu{0x80, 0x81, 0x0, 0x0, (uint8_t)sigTlv.size()};
  apdu.resize(apdu.size() + sigTlv.size());
  std::move(sigTlv.begin(), sigTlv.end(), apdu.begin() + 5);

  uint8_t response[128];
  uint8_t responseLength = 128;
  ESP_LOGD(TAG, "Auth1 APDU Length: %d, DATA: %s", apdu.size(), utils::bufToHexString(apdu.data(), apdu.size()).c_str());
  nfc.inDataExchange(apdu.data(), apdu.size(), response, &responseLength);
  ESP_LOGD(TAG, "Auth1 Response Length: %d, DATA: %s", responseLength, utils::bufToHexString(response, responseLength).c_str());
  homeKeyEndpoint::endpoint_t *foundEndpoint = nullptr;
  homeKeyIssuer::issuer_t *foundIssuer = nullptr;
  if (responseLength > 2 && response[responseLength - 2] == 0x90)
  {
    std::vector<uint8_t> persistentKey(32);
    uint8_t volatileKey[48];
    Auth1_keys_generator(persistentKey.data(), volatileKey);
    auto context = DigitalKeySecureContext(volatileKey);
    auto response_result = context.decrypt_response(response, responseLength - 2);
    ESP_LOGD(TAG, "Decrypted Length: %d, Data: %s", std::get<0>(response_result).size(), utils::bufToHexString(std::get<0>(response_result).data(), std::get<0>(response_result).size()).c_str());
    if (std::get<1>(response_result) > 0)
    {
      std::vector<BERTLV> decryptedTlv = BERTLV::unpack_array(std::vector<unsigned char>{std::get<0>(response_result).data(), std::get<0>(response_result).data()+std::get<1>(response_result)});
      BERTLV *signature = nullptr;
      BERTLV *device_identifier = nullptr;
      for (auto &data : decryptedTlv)
      {
        if(data.tag[0] == 0x4E)
        {
          device_identifier = &data;
        }
        if(data.tag[0] == 0x9E)
        {
          signature = &data;
        }
      }
      if(device_identifier == nullptr){
        commandFlow(homeKeyReader::kCmdFlowFailed);
        return std::make_tuple(foundIssuer, foundEndpoint, context, std::vector<uint8_t>{}, homeKeyReader::kFlowFailed);
      }
      for (auto &issuer : readerData.issuers)
      {
        for (auto &endpoint : issuer.endpoints)
        {
          if(!memcmp(endpoint.endpointId, device_identifier->value.data(), 6)){
            ESP_LOGD(TAG,"STD_AUTH: Found Matching Endpoint, ID: %s", utils::bufToHexString(endpoint.endpointId, sizeof(endpoint.endpointId)).c_str());
            foundEndpoint = &endpoint;
            foundIssuer = &issuer;
          }
        }
      }
      if(foundEndpoint != nullptr){
        std::vector<uint8_t> verification_hash_input_material(sizeof(readerData.reader_identifier) + sizeof(readerData.identifier) + endpointEphX.size() + readerEphX.size() + 30);
        size_t olen = 0;

        utils::simple_tlv(0x4D, readerIdentifier.data(), sizeof(readerData.reader_identifier) + sizeof(readerData.identifier), verification_hash_input_material.data(), &olen);
        utils::simple_tlv(0x86, endpointEphX.data(), endpointEphX.size(), verification_hash_input_material.data() + olen, &olen);
        utils::simple_tlv(0x87, readerEphX.data(), readerEphX.size(), verification_hash_input_material.data() + olen, &olen);
        utils::simple_tlv(0x4C, transactionIdentifier.data(), 16, verification_hash_input_material.data() + olen, &olen);
        utils::simple_tlv(0x93, deviceCtx, 4, verification_hash_input_material.data() + olen, &olen);
        mbedtls_ecp_keypair keypair;
        mbedtls_ecp_keypair_init(&keypair);

        uint8_t hash[32];

        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), verification_hash_input_material.data(), olen, hash);

        ESP_LOGD(TAG,"verification_hash_input_material: %s", utils::bufToHexString(hash, 32).c_str());
        mbedtls_mpi r;
        mbedtls_mpi s;

        mbedtls_mpi_init( &r );
        mbedtls_mpi_init( &s );
        mbedtls_ecp_group_load(&keypair.grp, MBEDTLS_ECP_DP_SECP256R1);
        int pubImport = mbedtls_ecp_point_read_binary(&keypair.grp, &keypair.Q, foundEndpoint->publicKey, sizeof(foundEndpoint->publicKey));
        ESP_LOGV(TAG,"public key import result: %d", pubImport);

        mbedtls_mpi_read_binary(&r, signature->value.data(), signature->value.size()/2);
        mbedtls_mpi_read_binary(&s, signature->value.data() + (signature->value.size() / 2), signature->value.size()/2);

        int result = mbedtls_ecdsa_verify(&keypair.grp, hash, 32, &keypair.Q, &r, &s);

        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);

        mbedtls_ecp_keypair_free(&keypair);

        ESP_LOGV(TAG,"signature verification result: %d", result);

        if (result == 0)
        {
          std::vector<uint8_t> cmdFlowRes = commandFlow(homeKeyReader::kCmdFlowSuccess);
          if (cmdFlowRes[0] == 0x90)
          {
            LOG(D, "Endpoint %s Authenticated via STANDARD Flow", utils::bufToHexString(foundEndpoint->endpointId, sizeof(foundEndpoint->endpointId), true).c_str());          }
            return std::make_tuple(foundIssuer, foundEndpoint, context, persistentKey, homeKeyReader::kFlowSTANDARD);
        }
        else if (device_identifier != nullptr)
        {
            return std::make_tuple(foundIssuer, foundEndpoint, context, persistentKey, homeKeyReader::kFlowATTESTATION);
        }
      }
      commandFlow(homeKeyReader::kCmdFlowFailed);
      return std::make_tuple(foundIssuer, foundEndpoint, context, std::vector<uint8_t>{}, homeKeyReader::kFlowFailed);
    }
    else
    {
      ESP_LOGW(TAG, "STANDARD Flow failed!");
      commandFlow(homeKeyReader::kCmdFlowFailed);
      return std::make_tuple(foundIssuer, foundEndpoint, context, std::vector<uint8_t>{}, homeKeyReader::kFlowFailed);
    }
  }
  ESP_LOGE(TAG, "Response Status not 0x90, something went wrong!");
  commandFlow(homeKeyReader::kCmdFlowFailed);
  return std::make_tuple(foundIssuer, foundEndpoint, DigitalKeySecureContext(), std::vector<uint8_t>{}, homeKeyReader::kFlowFailed);
}
