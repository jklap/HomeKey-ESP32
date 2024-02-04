#ifndef HOMEKEY_ESP32_SPAN_COMMANDS_H
#define HOMEKEY_ESP32_SPAN_COMMANDS_H

void deleteReaderData(const char *buf);
void pairCallback(bool isPaired);
void setFlow(const char *buf);
void setMqttConfiguration(const char *buf);
void setLogLevel(const char *buf);
void insertDummyIssuers(const char *buf);
void printIssuers(const char *buf);

#endif //HOMEKEY_ESP32_SPAN_COMMANDS_H
