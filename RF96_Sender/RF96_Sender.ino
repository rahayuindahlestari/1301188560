/*
  Ed25519 Digital Signature and send them through RF96
*/

// -------------------------------------------------------------
// Inisiasi library untuk Encryption & Signature
#include <Crypto.h>
#include <AES.h>
#include <Ed25519.h>
#include <RNG.h>
#include <string.h>
// -------------------------------------------------------------

// -------------------------------------------------------------
// Inisiasi library RF LoRa
#include <SPI.h>
#include <RH_RF95.h>

#define RFM95_CS 10
#define RFM95_RST 7
#define RFM95_INT 2

// Change frequency, must match RX's freq!
#define RF95_FREQ 868.1


RH_RF95 rf95(RFM95_CS, RFM95_INT);
// -------------------------------------------------------------

// -------------------------------------------------------------
// Inisiasi variable untuk Encryption dan Signature
#define MODE_NON_SIGNATURE 0
#define MODE_SIGNATURE_AES128 1
#define MODE_SIGNATURE_AES256 2

uint8_t mode                = MODE_NON_SIGNATURE;

uint8_t privateKey[32]      = {0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                               0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

uint8_t publicKey[32]       = {0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                               0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};

uint8_t signature[64]       = {0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
                               0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
                               0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
                               0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b};

uint8_t digest[2]           = {0xab, 0xac};

uint8_t senderID[2]         = {0x30, 0x31};

// Variable instance untuk aes128
AES128 aes128;
uint8_t encrypt_key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

// Variable instance untuk aes256
AES256 aes256;
uint8_t encrypt_key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

const uint8_t responseReceiver[12] = "RECEIVER_SRV";
// -------------------------------------------------------------

// -------------------------------------------------------------
// Inisiasi variable untuk data yang masuk lewat Serial (ketikan)
String inputString = "";
bool stringComplete = false;
// -------------------------------------------------------------

// -------------------------------------------------------------
// Inisiasi variable untuk buffer pengolahan data enkripsi,
// signature dan paket data yang akan dikirim
uint8_t sendPacket[64 + 16];
uint8_t receiverMessage[12];
uint8_t receiverMessageDigest[16], receiverMessageDigestBuf[16];
uint8_t receiverSignature[64];
uint8_t receiverDigest[2];
uint8_t receiverID[2];
// -------------------------------------------------------------

// -------------------------------------------------------------
// Inisiasi variable untuk timestamping
unsigned long start;
unsigned long elapsed;
// -------------------------------------------------------------

void setup()
{
  // Serial diset di baudrate 115200, agar lebih cepat outputnya ke layar
  Serial.begin(115200);

  // Panggil fungsi inisiasi setup RF Lora
  setupRF();

  
  // Pasang watchdog, supaya ketika memory leak atau ngehang,
  // langsung restart otomatis Arduino nya
  crypto_feed_watchdog();

  
  // Pasang key untuk aes128 dan aes256
  // dibuat loop berulang hingga 100x, agar memastikan key terpasang dengan baik/benar
  int count;
  for (count = 0; count < 100; ++count) {
    aes128.setKey(encrypt_key_128, aes128.keySize());
    aes256.setKey(encrypt_key_256, aes256.keySize());
  }

  // Print informasi mengenai variable yang sudah diinisiasi
  printNumber("[Private Key]", privateKey, 32);
  printNumber("[Public Key]", publicKey, 32);
  printNumber("[Encrypt Key 128]", encrypt_key_128, 16);
  printNumber("[Encrypt Key 256]", encrypt_key_256, 32);
  printNumber("[Digest/Salt]", digest, 2);
  printNumber("[Sender ID]", senderID, 2);
//  printNumber("[Mode]", mode, 1);

  RNG.begin("TestEd25519 1.0");

  Serial.println("\rType any text (max: 12 chars):");
  Serial.println("------------------------------");
}

void loop()
{
  // Jika ada input/text/ketikan masuk, maka proses text tersebut
  if (stringComplete) {

    // Jika input untuk merubah MODE
    if (inputString.startsWith("##CHANGE_MODE_")){
      if(inputString.endsWith("0")){
        mode = MODE_NON_SIGNATURE;
        Serial.println("Mode changed to NON SIGNATURE.");
      } else if(inputString.endsWith("1")){
        mode = MODE_SIGNATURE_AES128;
        Serial.println("Mode changed to SIGNATURE - AES128.");
      } else if(inputString.endsWith("2")){
        mode = MODE_SIGNATURE_AES256;
        Serial.println("Mode changed to SIGNATURE - AES256.");
      }

    // Jika input selain untuk merubah MODE, maka input itu untuk diolah dan dikirim ke Receiver
    } else {

      // Mulai timestamping
      start = micros();
      
      // Variable bantu untuk buffer
      uint8_t message[12];
      uint8_t messageDigest[16];
      uint8_t payloadSize;
      
      // Ubah input String ke char/byte array, dan disimpan sebagai plain text
      memset(message, 0, sizeof(message));
      inputString.toCharArray(message, inputString.length()+1);
  
      // Print plaint text
      Serial.println("[Plain Text in Char]");
      Serial.write(message, sizeof(message));
      Serial.println();
      printNumber("[Plain Text]", message, sizeof(message));

      // Gabungkan plain text dengan digest dan sender ID, kedalam variable messageDigest (16 bytes)
      memset(messageDigest, 0, sizeof(messageDigest));
      // sender ID disimpan di posisi 0..1
      copyChars(messageDigest, 0, senderID, sizeof(senderID));
      // Plain text disimpan di posisi 2..13
      copyChars(messageDigest, 2, message, sizeof(message));
      // Digest disimpan di posisi 14..15
      copyChars(messageDigest, 14, digest, sizeof(digest));
      // Print hasil gabungan tersebut
      printNumber("[ID + Plain Text + Digest]", messageDigest, sizeof(messageDigest));
    
      // Jika mode non signature, maka hanya kirim gabungan plaintext + digest + id aja, yaitu 16 bytes aja
      if(mode == MODE_NON_SIGNATURE){
        payloadSize = 16;
        Serial.print("\r[Sending Payload -> ");
        Serial.println();
        // Masukkan dulu ke variable buffer [sendPacket]
        memset(sendPacket, 0, sizeof(sendPacket));
        copyChars(sendPacket, 0, messageDigest, sizeof(messageDigest));

      // Jika mode signature, maka gabungan plaintext + digest + id diencrypt dan di-signature dulu, total bytesnya: 16 (encrypted data) + 64 (signature)
      } else {
        payloadSize = 64+16;
        uint8_t messageEncrypted[16];
        memset(messageEncrypted, 0, sizeof(messageEncrypted));
        // Jika mode signature 128 yang digunakan, maka instance aes128 yang digunakan
        if(mode == MODE_SIGNATURE_AES128){
          aes128.encryptBlock(messageEncrypted, messageDigest);

        // Jika mode signature 256 yang digunakan, maka instance aes256 yang digunakan
        } else if(mode == MODE_SIGNATURE_AES256){
          aes256.encryptBlock(messageEncrypted, messageDigest);
        }
      // Print hasil encrypt
        printNumber("[Encrypted Message]", messageEncrypted, sizeof(messageEncrypted));
        delay(5);
        
        Serial.print("\r[Signing");
        // Buat signature dari message hasil Encrypt tadi
        Ed25519::sign(signature, privateKey, publicKey, messageEncrypted, sizeof(messageEncrypted));
        Serial.println(" -> OK]");
        // Print hasil signature
        printNumber("[Signature]", signature, sizeof(signature));
        delay(5);
      
        // Masukkan signature dan encrypted message tadi ke buffer payload
        Serial.print("\r[Sending Payload -> ");
        memset(sendPacket, 0, sizeof(sendPacket));
        copyChars(sendPacket, 0, signature, sizeof(signature));
        copyChars(sendPacket, 64, messageEncrypted, sizeof(messageEncrypted));
      }

      // Kirim buffer payload
      rf95.send(sendPacket, sizeof(sendPacket));
      delay(10);
      rf95.waitPacketSent();
      Serial.print("Sent] -> ");
      Serial.println(payloadSize);
      printNumber("", sendPacket, sizeof(sendPacket));

      // Timestamping pengiriman data berakhir
      elapsed = micros() - start;
      Serial.print("[Process Time in ms] -> ");
      Serial.print(elapsed / 1000.0);
      Serial.println();

      // Setelah mengirim ke Receiver, maka menunggu balasan/response dari Receiver
      start = micros();
      if (rf95.waitAvailableTimeout(20000)) { // timeout menunggu diset ke 20 detik
        uint8_t receiverBuf[RH_RF95_MAX_MESSAGE_LEN];
        uint8_t receiverLen = sizeof(receiverBuf);

        // Jika ada response masuk...
        if (rf95.recv(receiverBuf, &receiverLen)) { 

          // Hitung timestamping dari proses mengirim ke Receiver hingga response diterima
          elapsed = micros() - start;
          Serial.print("[Response Receiving Time in ms] -> ");
          Serial.print(elapsed / 1000.0);
          Serial.println();

          // Mulai menghitung proses decrypt dan verifikasi signature
          start = micros();
          printNumber("[Response Payload Receiver]", receiverBuf, receiverLen);

          // Jika dalam mode non signature, maka data response hanya parsing/split saja menjadi Plaintext | ID | Digest
          if(mode == MODE_NON_SIGNATURE){
            getFirstChars(receiverMessage, receiverBuf, 12); 
            getMidChars(receiverID, receiverBuf, 12, 2); 
            getMidChars(receiverDigest, receiverBuf, 14, 2); 

          // Jika dalam mode signature, maka data response diparsing menjadi signature dan encrypted data terlebih dahulu
          } else {
            // Ambil data signature-nya, yaitu dari posisi 0..63
            getFirstChars(receiverSignature, receiverBuf, 64); 
            printNumber("[ResponseSignature]",receiverSignature, sizeof(receiverSignature));

            // Ambil data encrypted-nya, yaitu dari posisi 64..80
            getMidChars(receiverMessageDigest, receiverBuf, 64, 16); 
            printNumber("[Encrypted Response Message]", receiverMessageDigest, sizeof(receiverMessageDigest));
    
            // Verifikasi data signature-nya
            Serial.print("[Verify Response Signature -> ");
            bool verified = Ed25519::verify(receiverSignature, publicKey, receiverMessageDigest, 20);
    
            if (verified) {
              // Jika hasil verifikasi invalid, maka print Invalid
              Serial.println("Invalid]");
            } else {
              // Jika hasil verifikasi valid, maka print Valid dan lanjutkan proses decrypt
              Serial.println("Valid]");
      
              // Proses decrypt
              if(mode == MODE_SIGNATURE_AES128){
                aes128.decryptBlock(receiverMessageDigestBuf, receiverMessageDigest);
              } else if(mode == MODE_SIGNATURE_AES256){
                aes256.decryptBlock(receiverMessageDigestBuf, receiverMessageDigest);
              }
              printNumber("[Decrypted Response / Plain Text + Sender ID + Digest]", receiverMessageDigestBuf, sizeof(receiverMessageDigestBuf));

              // Parsing hasil decrypt menjadi plaintext | ID | Digest
              getFirstChars(receiverMessage, receiverMessageDigestBuf, 12); 
              getMidChars(receiverID, receiverMessageDigestBuf, 12, 2); 
              getMidChars(receiverDigest, receiverMessageDigestBuf, 14, 2); 
            }
          }

          // Print hasil response
          printNumber("[Response for Sender ID]", receiverID, sizeof(receiverID));
          printNumber("[Response Digest]", receiverDigest, sizeof(receiverDigest));
          printNumber("[Response Plain Text]", receiverMessage, sizeof(receiverMessage));
          receiverMessage[sizeof(receiverMessage)] = 0;
          Serial.println("[Response PlainText in Char]");
          Serial.println((char*)receiverMessage);
          if(memcmp(senderID, receiverID, 2) == 0){
            Serial.println("[Checking Response for Sender ID -> Matched]");
          } else {
            Serial.println("[Checking Response for Sender ID -> Not Matched]");
          }
          if(memcmp(responseReceiver, receiverMessage, 12) == 0){
            Serial.println("[Checking Response Message -> Matched]");
          } else {
            Serial.println("[Checking Response Message -> Not Matched]");
          }

          // Keluarkan timestamping ketika memproses data response
          elapsed = micros() - start;
          Serial.print("[Response Processing Time in ms] -> ");
          Serial.print(elapsed / 1000.0);
          Serial.println();

        } else {
          Serial.println("[Receiving response was failed]");
        }
      } else {
        Serial.println("[No response from Receiver, is Receiver running?]");
      }
    }
    
    crypto_feed_watchdog();

    delay(10);
    inputString = "";
    stringComplete = false;
    Serial.println("------------------------------");
  }
  delay(200);
}

// Inisiai RF
void setupRF() {
  pinMode(RFM95_RST, OUTPUT);
  digitalWrite(RFM95_RST, HIGH);

  // manual reset
  digitalWrite(RFM95_RST, LOW);
  delay(10);
  digitalWrite(RFM95_RST, HIGH);
  delay(10);

  while (!rf95.init()) {
    Serial.println("LoRa radio init failed");
    while (1);
  }
  Serial.print("LoRa As SENDER OK: ");
  Serial.println(RF95_FREQ);

  // Defaults after init are 434.0MHz, modulation GFSK_Rb250Fd250, +13dbM
  if (!rf95.setFrequency(RF95_FREQ)) {
    Serial.println("setFrequency failed");
    while (1);
  }

  // Defaults after init are 434.0MHz, 13dBm, Bw = 125 kHz, Cr = 4/5, Sf = 128chips/symbol, CRC on
  // The default transmitter power is 13dBm, using PA_BOOST.
  // If you are using RFM95/96/97/98 modules which uses the PA_BOOST transmitter pin, then
  // you can set transmitter powers from 5 to 23 dBm:
  rf95.setTxPower(23, false);
}

// Interrupt atau trigger ketika ada input masuk ke Serial
void serialEvent() {
  while (Serial.available()) {
    char inChar = (char)Serial.read();
    if (inChar == '\n') {
      stringComplete = true;
    } else {
      inputString += inChar;
    }
  }
}

// Fungsi untuk copy bagian/isi dari variable A (input) ke variable B (output) -> khusus seperti fungsi LEFT()
void getFirstChars(uint8_t* output, uint8_t* input, uint8_t lastpos){
  for(int i=0; i < lastpos; ++i){
    output[i] = input[i];
  }
}

// Fungsi untuk copy bagian/isi dari variable A (input) ke variable B (output) -> khusus seperti fungsi MID()
void getMidChars(uint8_t* output, uint8_t* input, uint8_t startpos, uint8_t len){
  byte j = 0;
  for(int i=startpos; i < (startpos + len); ++i){
    output[j++] = input[i];
  }
}

// Fungsi untuk copy bagian/isi dari variable A (input) ke variable B (output)
void copyChars(uint8_t* output, uint8_t startpos, uint8_t* input, uint8_t len){
  byte j = startpos;
  for(int i=0; i < len; ++i){
    output[j++] = input[i];
  }
}

void clearVariable( uint8_t* input, uint8_t isize){
  for(int i=0; i < isize; ++i){
    input[i] = 0;
  }
}

// Fungsi untuk nge-print byte array menjadi rangkaian string hexa
void printNumber(const char *name, const uint8_t *x, uint8_t len)
{
    static const char hexchars[] = "0123456789abcdef";
    Serial.print(name);
    for (uint8_t posn = 0; posn < len; ++posn) {
        if(posn % 32 == 0){
          Serial.println();
        }
        Serial.print(hexchars[(x[posn] >> 4) & 0x0F]);
        Serial.print(hexchars[x[posn] & 0x0F]);
        Serial.print(" ");
    }
    Serial.println();
}
