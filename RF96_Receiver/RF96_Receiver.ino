// Inisiasi library untuk Encryption & Signature
#include <Crypto.h>
#include <AES.h>
#include <Ed25519.h>
#include <RNG.h>
#include <string.h>

// Inisiasi library RF LoRa
#include <SPI.h>
#include <RH_RF95.h>

#define RFM95_CS 10
#define RFM95_RST 7
#define RFM95_INT 2

// Change frequency, must match RX's freq!
#define RF95_FREQ 868.1

// Singleton instance of the radio driver
RH_RF95 rf95(RFM95_CS, RFM95_INT);

// Inisiasi variable untuk Encryption dan Signature
#define MODE_NON_SIGNATURE 0
#define MODE_SIGNATURE_AES128 1
#define MODE_SIGNATURE_AES256 2

uint8_t mode                = MODE_NON_SIGNATURE;

uint8_t privateKey[32]      = {0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xac, 0x7f, 0xb4,
                               0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0x70};

uint8_t publicKey[32]       = {0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                               0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};

uint8_t signature[64]       = {0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
                               0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
                               0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
                               0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b};

uint8_t digest[2]           = {0xba, 0xbc};

// Variable instance untuk aes128
AES128 aes128;
uint8_t encrypt_key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

// Variable instance untuk aes256
AES256 aes256;
uint8_t encrypt_key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};


// Inisiasi variable untuk data yang masuk lewat Serial (ketikan)
String inputString = "";
bool stringComplete = false;

// Inisiasi variable untuk buffer pengolahan data enkripsi,
// signature dan paket data yang akan dikirim
uint8_t receiverMessage[12];
uint8_t receiverMessageDigest[16], receiverMessageDigestBuf[16];
uint8_t receiverSignature[64];
uint8_t receiverDigest[2];
uint8_t receiverID[2];

uint8_t responseMessage[12] = "RECEIVER_SRV";
uint8_t responseMessageDigest[16];
uint8_t responseMessageDigestEncrypted[16];
uint8_t responseSignature[64];
uint8_t responsePacket[64 + 16];

// Inisiasi variable untuk timestamping
unsigned long start;
unsigned long elapsed;

void setup() 
{   
  // Serial diset di baudrate 115200, agar lebih cepat outputnya ke layar
  Serial.begin(115200);
  // Panggil fungsi inisiasi setup RF Lora
  setupRF();

  int count;
  // Pasang watchdog, supaya ketika memory leak atau ngehang,
  // langsung restart otomatis Arduino nya
  crypto_feed_watchdog();
  // Pasang key untuk aes128 dan aes256
  // dibuat loop berulang hingga 100x, agar memastikan key terpasang dengan baik/benar
  for (count = 0; count < 10000; ++count) {
    aes128.setKey(encrypt_key_128, aes128.keySize());
    aes256.setKey(encrypt_key_256, aes256.keySize());
  }

  // Print informasi mengenai variable yang sudah diinisiasi
  printNumber("[Private Key]", privateKey, 32);
  printNumber("[Public Key]", publicKey, 32);
  printNumber("[Encrypt Key 128]", encrypt_key_128, 16);
  printNumber("[Encrypt Key 256]", encrypt_key_256, 32);
  printNumber("[Digest/Salt]", digest, 2);

  RNG.begin("TestEd25519 1.0");
  mode = MODE_NON_SIGNATURE;
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
    }
    delay(10);
    inputString = "";
    stringComplete = false;
  }

  if (rf95.available())
  {
    uint8_t receiverBuf[RH_RF95_MAX_MESSAGE_LEN];
    uint8_t receiverLen = sizeof(receiverBuf);

    // Mulai menghitung proses decrypt dan verifikasi signature
    start = micros();
    if (rf95.recv(receiverBuf, &receiverLen))
    {
      printNumber("[Payload Receiver]", receiverBuf, receiverLen);
      // Jika dalam mode non signature, maka data response hanya parsing/split saja menjadi Plaintext | ID | Digest
      if(mode == MODE_NON_SIGNATURE){
        getFirstChars(receiverID, receiverBuf, 2); 
        getMidChars(receiverDigest, receiverBuf, 14, 2); 
        getMidChars(receiverMessage, receiverBuf, 2, 12); 
     // Jika dalam mode signature, maka data response diparsing menjadi signature dan encrypted data terlebih dahulu
      } else {
        // Ambil data signature-nya, yaitu dari posisi 0..63
        getFirstChars(receiverSignature, receiverBuf, 64); 
        printNumber("[Signature]",receiverSignature, sizeof(receiverSignature));

        // Ambil data encrypted-nya, yaitu dari posisi 64..80
        getMidChars(receiverMessageDigest, receiverBuf, 64, 16); 
        printNumber("[Encrypted Message]", receiverMessageDigest, sizeof(receiverMessageDigest));

        // Verifikasi data signature-nya
        Serial.print("[Verify Signature -> ");
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
          printNumber("[Decrypted Message / Sender ID + Plain Text + Digest]", receiverMessageDigestBuf, sizeof(receiverMessageDigestBuf));

          // Parsing hasil decrypt menjadi plaintext | ID | Digest
          getFirstChars(receiverID, receiverMessageDigestBuf, 2); 
          getMidChars(receiverDigest, receiverMessageDigestBuf, 14, 2); 
          getMidChars(receiverMessage, receiverMessageDigestBuf, 2, 12); 
        }
      }

      // Print hasil response
      printNumber("[Sender ID]", receiverID, sizeof(receiverID));
      printNumber("[Digest]", receiverDigest, sizeof(receiverDigest));
      printNumber("[Plain Text]", receiverMessage, sizeof(receiverMessage));
      receiverMessage[sizeof(receiverMessage)] = 0;
      Serial.println("[PlainText in Char]");
      Serial.println((char*)receiverMessage);
      Serial.println();

      // Send a reply, format data:
      // RECEIVER_SRV|SENDER_ID|DIGEST
      memset(responseMessageDigest, 0, sizeof(responseMessageDigest));
      copyChars(responseMessageDigest, 0, responseMessage, sizeof(responseMessage));
      copyChars(responseMessageDigest, 12, receiverID, sizeof(receiverID));
      copyChars(responseMessageDigest, 14, digest, sizeof(digest));
      printNumber("[Response Text With Digest]", responseMessageDigest, sizeof(responseMessageDigest));

      // Keluarkan timestamping ketika memproses data response
      elapsed = micros() - start;
      Serial.print("[Processing Data From Sender in ms] -> ");
      Serial.print(elapsed / 1000.0);
      Serial.println();


      start = micros();
      // Jika mode non signature, maka hanya kirim gabungan plaintext + digest + id aja, yaitu 16 bytes aja
      if(mode == MODE_NON_SIGNATURE){
        Serial.println("\r[Sending Response Payload]");
        memset(responsePacket, 0, sizeof(responsePacket));
        copyChars(responsePacket, 0, responseMessageDigest, sizeof(responseMessageDigest));
      // Jika mode signature, maka gabungan plaintext + digest + id diencrypt dan di-signature dulu, total bytesnya: 16 (encrypted data) + 64 (signature)
      } else {
        memset(responseMessageDigestEncrypted, 0, sizeof(responseMessageDigestEncrypted));
        // Jika mode signature 128 yang digunakan, maka instance aes128 yang digunakan
        if(mode == MODE_SIGNATURE_AES128){
          aes128.encryptBlock(responseMessageDigestEncrypted, responseMessageDigest);

        // Jika mode signature 256 yang digunakan, maka instance aes256 yang digunakan
        } else if(mode == MODE_SIGNATURE_AES256){
          aes256.encryptBlock(responseMessageDigestEncrypted, responseMessageDigest);
        }
        // Print hasil encrypt
        printNumber("[Encrypted Response Message]", responseMessageDigestEncrypted, sizeof(responseMessageDigestEncrypted));
        Serial.print("\r[Signing Response");
        // Buat signature dari message hasil Encrypt tadi
        Ed25519::sign(responseSignature, privateKey, publicKey, responseMessageDigestEncrypted, sizeof(responseMessageDigestEncrypted));
        // Print hasil signature
        Serial.println(" -> OK]");

        // Masukkan signature dan encrypted message tadi ke buffer payload
        Serial.println("\r[Sending Response Payload]");
        memset(responsePacket, 0, sizeof(responsePacket));
        copyChars(responsePacket, 0, responseSignature, sizeof(responseSignature));
        copyChars(responsePacket, 64, responseMessageDigestEncrypted, sizeof(responseMessageDigestEncrypted));
      }

      // Kirim buffer payload
      rf95.send(responsePacket, sizeof(responsePacket));
      delay(10);
      rf95.waitPacketSent();
      printNumber("[Response Payload Sent]", responsePacket, sizeof(responsePacket));

      // Hitung timestamping dari proses mengirim ke Receiver hingga response diterima
      elapsed = micros() - start;
      Serial.print("[Processing Response To Sender in ms] -> ");
      Serial.print(elapsed / 1000.0);
      Serial.println();


      clearVariable(receiverMessageDigestBuf, sizeof(receiverMessageDigestBuf));
      clearVariable(receiverMessageDigest, sizeof(receiverMessageDigest));
      clearVariable(receiverMessage, sizeof(receiverMessage));
      clearVariable(receiverDigest, sizeof(receiverDigest));
      clearVariable(receiverSignature, sizeof(receiverSignature));
    }
    else
    {
      Serial.println("RECEIVER FAILED");
    }
    Serial.println("------------------------------");
  }
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
  Serial.print("LoRa As RECEIVER OK: ");
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
