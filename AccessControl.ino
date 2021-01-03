#include <Wire.h>
#include "RTClib.h"
#include <SPI.h>
#include <Ethernet.h>
#include <LiquidCrystal.h>
#include <SD.h>
#include <MFRC522.h>
#include <utility/w5100.h>

//==============================================================
//====================Tag Structures ===========================
struct LastTag {
  String ID;
  unsigned long dt;
};
LastTag lastTag[10];
LastTag lastIP[10];
//=======================================================================================
//============================== Config Variables =======================================
IPAddress IP(192, 168, 1, 100);
IPAddress gateway(192, 168, 1, 1);
IPAddress subnet(255, 255, 255, 0);
EthernetServer server(80);  // create a server at port 80
EthernetClient cln;
unsigned int MyID = 1;
IPAddress ServerIP;
unsigned int ServerPort = 100;
byte IgnoreInterval = 30;
boolean SendTCP = true;
boolean LogData = true;
boolean LCDData = false;
boolean Bp = true;
unsigned int deleteInterval = 90;
byte lc = 0;

//================================================================
//==================== Common Variables ==========================
#define RError 40
#define ROK 41
RTC_DS1307 RTC;
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
File myFile;
unsigned long srvr = 0;
byte TCPTry = 0;
unsigned long TCPLast = 0;
unsigned long mil = 0;
#define SS_PIN 49
#define RST_PIN 48
#define BP 28
#define BL 29
#define SS 53
MFRC522 mfrc522(SS_PIN, RST_PIN);  // Create MFRC522 instance.
MFRC522::MIFARE_Key key4;
LiquidCrystal lcd(22, 23, 24, 25, 26, 27);
unsigned long BLtmr;
unsigned long CLtmr;
unsigned long LCDtmr;
unsigned long DEltmr;
String LastAdr = "";

//================================================================
//==================== Start SETUP ===============================
void setup() {
  //Serial Initialization
  Serial.begin(9600);
  SPI.begin();
  Serial.println("Starting Moradzadeh Access System ...");

  //==================== Setup Pins ==============================
  pinMode(RError, OUTPUT);
  pinMode(ROK, OUTPUT);
  digitalWrite(RError, HIGH);
  digitalWrite(ROK, HIGH);
  pinMode(SS_PIN, OUTPUT);
  pinMode(BL, OUTPUT);
  pinMode(BP, OUTPUT);

  //==================== Setup RFID ==============================
  // digitalWrite(SS_PIN, LOW);
  mfrc522.PCD_Init(); // Init MFRC522 card

  //==================== Setup LCD ===============================
  digitalWrite(BL, HIGH);
  lcd.begin(16, 2);
  lcd.setCursor(7, 0);
  lcd.print("HI");
  lcd.setCursor(0, 1);
  lcd.print("STARTING .      ");


  //==================== Initiate the RTC ========================
  Wire.begin();
  RTC.begin();
  if (! RTC.isrunning()) {
    Serial.println("Error : RTC is NOT running");
    lcd.setCursor(0, 0);
    lcd.print("ERROR           ");
    lcd.setCursor(0, 1);
    lcd.print("RTC NOT RUNNING ");
    byte c = 0;
    while (true)
    {
      c = 1 - c;
      digitalWrite(RError, c);
      delay(500);
    }
  }
  lcd.setCursor(0, 1);
  lcd.print("STARTING . .    ");
  //==================== Check RTC Time ==========================
  DateTime now = RTC.now();
  DateTime compiled = DateTime(__DATE__, __TIME__);
  Serial.println(__DATE__);
  Serial.println(__TIME__);
  if (now.unixtime() < compiled.unixtime()) {
    Serial.println("RTC is older than compile time! Updating");
    RTC.adjust(DateTime(__DATE__, __TIME__));
  }
  Serial.print("Current Time : ");
  Serial.println(getTime());
  Serial.println("RTC Setup Complete");
  lcd.setCursor(0, 1);
  lcd.print("STARTING . . .  ");
  //==================== Initiate SD Card =========================
  pinMode(53, OUTPUT);
  if (!SD.begin(4)) {
    Serial.println("Error : SD initialization failed!");
    lcd.setCursor(0, 0);
    lcd.print("ERROR           ");
    lcd.setCursor(0, 1);
    lcd.print(" SD NOT RUNNING ");
    digitalWrite(RError, LOW);
    byte c = 0;
    while (true)
    {
      c = 1 - c;
      digitalWrite(RError, c);
      delay(500);
    }
  }
  Serial.println("SD Setup Complete");
  lcd.setCursor(0, 1);
  lcd.print("STARTING . . . . ");
  //==================== Reading Config File ======================
  LoadConfig();
  Beep(2);
  lcd.setCursor(0, 1);
  lcd.print("INITIATE COMPLET");
  delay(500);
  digitalWrite(ROK, HIGH);
  digitalWrite(RError, LOW);

}

//==================== END SETUP =====================================
//====================================================================


//======================================================================
//==================== Begin LOOP ======================================
void loop() {
  mil = millis();
  //==================== Check LCD Data ================================
  if (mil - LCDtmr >= 1000) {
    LCDtmr = mil;
    CheckLCD();
  }

  //====================================================================
  //==================== Check Network =================================
  if (mil - CLtmr >= 1000) {
    CLtmr = mil;
    CheckClient();
  }


  //=====================================================================
  //==================== Check Delete Time ================================
  if (mil - DEltmr >= 3600000) {
    DEltmr = mil;
    CheckDelete();
  }


  //====================================================================
  //==================== Check RFID Readers ============================
  if ( ! mfrc522.PICC_IsNewCardPresent())
    return;


  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial())
    return;


  // ====================== New Tag Found ==============================
  // ====================== Get Tag Type ===============================
  byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.print("PICC type: ");
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
  if (  piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println("This System only works with MIFARE Classic cards.");
    lcd.setCursor(0, 1);
    lcd.print("  Invalid Card  ");
    Beep(0);
    return;
  }

  //============================================================
  // ============== Get Tag UID ================================
  Serial.print("Card UID:");
  String out = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    out += GetHex(mfrc522.uid.uidByte[i]);
  }
  out.toUpperCase();
  Serial.println(out);



  //====================================================================
  //==================== Check Tag =====================================
  CheckTag(out);

  // Halt PICC
  mfrc522.PICC_HaltA();

  // Stop encryption on PCD
  mfrc522.PCD_StopCrypto1();

}
//==================== END LOOP ======================================
//====================================================================


void CheckLCD() {
  if (LCDData) {
    if (mil - BLtmr >= 3000) {
      LCDData = false;
      BLtmr = mil;
      lcd.setCursor(0, 0);
      lcd.print(getTimeMin());
      lcd.setCursor(0, 1);
      lcd.print("                ");
    }
  }
  else
  {
    lc =  1 - lc;
    lcd.setCursor(0, 1);
    lcd.print("                ");
    lcd.setCursor(0, 0);

    if (lc == 0)
      lcd.print(getTimeMin());
    else
      lcd.print(getTimeMinNo());
  }
}

String GetHex(int b) {
  String out;
  out += b < 0x10 ? "0" : "";
  out += String(b, HEX);
  return out;
}


void Beep(int type) {
  if (!Bp)
    return;
  switch (type) {
    case 0:
      digitalWrite(BP, HIGH);
      delay(100);
      digitalWrite(BP, LOW);
      delay(100);
      digitalWrite(BP, HIGH);
      delay(100);
      digitalWrite(BP, LOW);
      delay(100);
      digitalWrite(BP, HIGH);
      delay(100);
      digitalWrite(BP, LOW);
      break;
    case 1:
      digitalWrite(BP, HIGH);
      delay(300);
      digitalWrite(BP, LOW);
      delay(100);
      digitalWrite(BP, HIGH);
      delay(100);
      digitalWrite(BP, LOW);
      break;
    case 2:
      digitalWrite(BP, HIGH);
      delay(500);
      digitalWrite(BP, LOW);
      break;
  }
}



//=====================================================================
//==================== Check Delete Time ================================
void CheckDelete() {
  if (deleteInterval != 0) {
    String d = GetDelDirName();
    if (d != "") {
      char dr[21];
      d.toCharArray(dr, 8);
      Serial.print("Want To Delete : ");
      Serial.println(dr);
      if (SD.exists(dr)) {
        File root = SD.open(dr);
        while (true) {
          File entry =  root.openNextFile();
          if (!entry) break;
          String s = d + "/" + String(entry.name());
          char de[21];
          s.toCharArray(de, s.length() + 1);
          Serial.println(de);
          delay(2000);
          if (SD.remove(de)) {
            Serial.print("File ");
            Serial.print(de);
            Serial.println(" Removed");
          }
          else
          {
            Serial.print("File ");
            Serial.print(de);
            Serial.println(" NOT Removed");
          }

        }

        if (SD.rmdir(dr))
          Serial.println("Directory Removed");
        else
          Serial.println("Directory Not Removed");
      }
    }

  }
}


//====================================================================
//==================== Network Func ==================================
void CheckClient() {
  EthernetClient client = server.available();  // try to get client
  if (client) {  // got client?
    lcd.setCursor(0, 0);
    lcd.print("  PLEASE WAIT   ");
    lcd.setCursor(0, 1);
    lcd.print("NETWORK RESPONSE");
    while (client.connected()) {
      Serial.println("Transaction Start");
      if (client.available()) {   // client data available to read
        String c = client.readString(); // read 1 byte (character) from client
        Serial.println("Request : " + c);
        String Adr = c.substring(5, c.indexOf(" HTTP/1.1"));
        Adr = getValue(Adr, '?', 0);
        // send a standard http response header
        client.println("HTTP/1.1 200 OK");
        byte rip[4];
        client.getRemoteIP(rip);
        String ip = String(rip[0]) + "." + String(rip[1]) + "." + String(rip[2]) + "." + String(rip[3]) ;
        Serial.println(ip);
        String et = getValue(Adr, '.', 1);
        //Check For Login Info  : username=DataNet&password=p@ssw0rd
        if (et == "dne")
        {
          String uid = c.substring(c.indexOf("username=") + 9, c.indexOf("&password="));
          uid.toLowerCase();
          String pwd =  c.substring(c.indexOf("&password=") + 10);
          Serial.println("UID : " + uid);
          Serial.println("PWD : " + pwd);
          String pw = "";
          myFile = SD.open("CtrlPwd.dat",  O_READ);
          if (myFile) {
            while (myFile.available())
            {
              pw += char(myFile.read());
            }
          }
          // Add IP To IP List
          if (uid == "datanet" && pwd == pw)
          {
            for (int i = 0; i < 10; i++) {
              if (lastIP[i].dt == 0) {
                lastIP[i] = {ip, mil};
                client.println("Content-Type: text/html");
                client.println("Connection: close");
                client.println();
                client.println("<html>");
                client.println("<body><script>window.location='home.htm';</script></body>");
                client.println("</html>");
                //Adr = LastAdr;
                //break;
                delay(1);      // give the web browser time to receive the data
                client.stop();
                lcd.setCursor(0, 0);
                lcd.print(getTimeMin());
                lcd.setCursor(0, 1);
                //LoadConfig();
                // Serial.println("Configuration Loads Successfull");
                lcd.print("                ");
                return;
              }
            }
          }
        }

        // Delete Expired IP From IP List
        for (int i = 0; i < 10; i++) {
          if (lastIP[i].dt > 0) {
            if ((mil - lastIP[i].dt) > 600000)
              lastIP[i] = {"", 0};
          }
        }
        // Check if Tag exists in ignore tag list
        bool ext = false;
        for (int i = 0; i < 10; i++) {
          if (lastIP[i].ID == ip) {
            Serial.println(ip + " Exists at : " + i);
            lastIP[i].dt = mil;
            ext = true;
            break;
          }
        }

        
        if (ext == false && et!="png") {
          Serial.print("IP Not Authorized");
          LastAdr = Adr;
          Adr = "Login.htm";
        }

        Serial.println("Requested Ext : " + et);

        if (et == "js")
          client.println("Content-Type: application/javascript");

        else if (et == "gif")
          client.println("Content-Type: image/gif");

        else if (et == "png")
          client.println("Content-Type: image/png");

        else if (et == "css")
          client.println("Content-Type: text/css");

        else if (et == "apc")
          client.println("Content-Type: text/cache-manifest");
        else if (et == "do") {
          //_txtTag=FF5B66B4,Abbas Moradzadeh%05CD8F75,Mojtaba Kiani%0C8FEBBD,Mohsen Zare%%&_IP=192.168.1.100&_SubMask=255.255.255.0&_GateWay=192.168.1.1&_MyID=1&_ServerIP=192.168.1.10&_ServerPort=100&_IgnoreInterval=10&_DeleteInterval=90&_Beep=ON&_LogData=ON&_SendData=ON&_txtPwd=&_txtPwdConf=&SetButton=  %D8%B0%D8%AE%DB%8C%D8%B1%D9%87
          String tx = c.substring(c.indexOf("_txtTag=") + 8, c.indexOf("&_IP="));
          tx.replace("+", " ");
          tx.replace("%2C", ",");
          tx.replace("%0D%0A", "%");
          Serial.println("Recieved Tag Data : " + tx);
          int cr = 0;
          myFile = SD.open("Tag.txt",  O_CREAT | O_WRITE | O_TRUNC);
          while (true)
          {
            String q = getValue(tx, '%', cr); //tx.substring(0, tx.indexOf("%0D%0A%"));
            cr += 1;
            Serial.println(q);
            if (q.length() > 8) {
              myFile.println(q);
            }
            if (q == "")
            {
              break;
            }
          }
          myFile.close();
          Serial.println("Tag Data Saved");
          myFile = SD.open("Config.txt",  O_CREAT | O_WRITE | O_TRUNC);
          if (myFile)
          {
            myFile.println(c.substring(c.indexOf("_IP=") + 4, c.indexOf("&_SubMask=")));
            myFile.println(c.substring(c.indexOf("_SubMask=") + 9, c.indexOf("&_GateWay=")));
            myFile.println(c.substring(c.indexOf("_GateWay=") + 9, c.indexOf("&_MyID=")));
            myFile.println(c.substring(c.indexOf("_MyID=") + 6, c.indexOf("&_ServerIP=")));
            myFile.println(c.substring(c.indexOf("_ServerIP=") + 10, c.indexOf("&_ServerPort=")));
            myFile.println(c.substring(c.indexOf("_ServerPort=") + 12, c.indexOf("&_IgnoreInterval=")));
            myFile.println(c.substring(c.indexOf("_IgnoreInterval=") + 16, c.indexOf("&_DeleteInterval=")));
            myFile.println(c.substring(c.indexOf("_DeleteInterval=") + 16, c.indexOf("&_Beep=")));
            myFile.println(c.substring(c.indexOf("_LogData=") + 9, c.indexOf("&_SendData=")));
            myFile.println(c.substring(c.indexOf("_SendData=") + 10, c.indexOf("&_txtPwd=")));
            myFile.println(c.substring(c.indexOf("_Beep=") + 6, c.indexOf("&_LogData=")));
          }
          myFile.close();
          Serial.println("Config Data Saved");

          //&_txtPwd=&_txtPwdConf=&SetButton=
          if (c.substring(c.indexOf("_txtPwd=") + 8, c.indexOf("&_txtPwdConf=")) != "" && c.substring(c.indexOf("_txtPwd=") + 8, c.indexOf("&_txtPwdConf=")) == c.substring(c.indexOf("_txtPwdConf=") + 12, c.indexOf("&SetButton="))) {
            myFile = SD.open("CtrlPwd.dat",  O_CREAT | O_WRITE | O_TRUNC);
            if (myFile)
            {
              myFile.print(c.substring(c.indexOf("_txtPwd=") + 8, c.indexOf("&_txtPwdConf=")));
              Serial.println("Password Changed");
            }
            myFile.close();
          }


          client.println("Content-Type: text/html");
          client.println("Connection: close");
          client.println();
          client.println("<html>");
          client.println("<meta charset='UTF-8'>");
          client.println("<head>");
          client.println("</head>");
          client.println("<body><div width='100%' align='center'><br><br><img src='logo2200.png'>");
          client.println("<br><br><h1 style=font-family:'""b titr"",Arial'></h1>");
          client.println("<script>");
          client.println("window.location='home.htm';");
          client.println("</script></div>");
          client.println("</body>");
          client.println("</html>");
          break;
        }
        else
          client.println("Content-Type: text/html");

        client.println("Connection: close");
        client.println();
        // send web page

        //Adr.trim();
        if (Adr == "")
          Adr = "Home.htm";
        Serial.print("Requested Address : |"); Serial.println(Adr + "|");
        char b[Adr.length() + 1];
        Adr.toCharArray(b, Adr.length() + 1);
        Serial.println(b);
        if (SD.exists(b)) {
          myFile = SD.open(Adr, O_READ);       // open web page file
          if (myFile) {
            byte clientBuf[512];
            int clientCount = 0;

            while (myFile.available())
            {
              clientBuf[clientCount] = myFile.read();
              clientCount++;

              if (clientCount > 511)
              {
                client.write(clientBuf, 512);
                clientCount = 0;
              }
            }
            if (clientCount > 0) client.write(clientBuf, clientCount);
            myFile.close();
            Serial.println("Response Complete");
            myFile.close();
          }
          break;
        }
        else {
          Serial.print("File Not Found");
          break;
        }
      }


    }
    delay(1);      // give the web browser time to receive the data
    client.stop();
    lcd.setCursor(0, 0);
    lcd.print(getTimeMin());
    lcd.setCursor(0, 1);
    //LoadConfig();
    // Serial.println("Configuration Loads Successfull");
    lcd.print("                ");

  }
}


//====================================================================
//==================== Public Func ===================================
String getValue(String data, char separator, int index)
{
  int found = 0;
  int strIndex[] = {
    0, -1
  };
  int maxIndex = data.length() - 1;
  for (int i = 0; i <= maxIndex && found <= index; i++) {
    if (data.charAt(i) == separator || i == maxIndex) {
      found++;
      strIndex[0] = strIndex[1] + 1;
      strIndex[1] = (i == maxIndex) ? i + 1 : i;
    }
  }
  return found > index ? data.substring(strIndex[0], strIndex[1]) : "";
}

//====================================================================
String GetTagHex(String Tag) {
  String out = "";

  for (int i = 0; i < Tag.length() / 4; i++) {
    byte p = 0;
    for (int j = 3; j >= 0; j--) {
      byte c = Tag.substring(i * 4 + j, i * 4 + j + 1).toInt();
      switch (j) {
        case 0 :
          p += c * 8;
          break;
        case 1 :
          p += c * 4;
          break;
        case 2 :
          p += c * 2;
          break;
        case 3 :
          p += c ;
          break;
      }
      // Serial.print(p);
      // Serial.print( ":" + String(pow(2,(3-j))) + ":" + String(c) + "-");
    }
    // Serial.print("|") ;
    out += String(p, HEX);
  }
  Serial.println("");
  return out;
}

//====================================================================
String getTime() {
  DateTime now = RTC.now();
  return String(now.year()) + "/" + (now.month() < 10 ? "0" : "") + String(now.month()) + "/" + (now.day() < 10 ? "0" : "") + String(now.day()) + " " + (now.hour() < 10 ? "0" : "") + String(now.hour()) + ":" + (now.minute() < 10 ? "0" : "") + String(now.minute()) + ":" + (now.second() < 10 ? "0" : "") + String(now.second());
}

String getTimeMin() {
  DateTime now = RTC.now();
  return String(now.year()) + "/" + (now.month() < 10 ? "0" : "") + String(now.month()) + "/" + (now.day() < 10 ? "0" : "") + String(now.day()) + " " + (now.hour() < 10 ? "0" : "") + String(now.hour()) + ":" + (now.minute() < 10 ? "0" : "") + String(now.minute());
}

String getTimeMinNo() {
  DateTime now = RTC.now();
  return String(now.year()) + "/" + (now.month() < 10 ? "0" : "") + String(now.month()) + "/" + (now.day() < 10 ? "0" : "") + String(now.day()) + " " + (now.hour() < 10 ? "0" : "") + String(now.hour()) + " " + (now.minute() < 10 ? "0" : "") + String(now.minute());
}

//====================================================================
int GetMin() {
  // return 1;
  DateTime now = RTC.now();
  return now.hour() * 100 + now.minute();
}


//====================================================================
//==================== Check Tag =====================================
void CheckTag(String Tag) {

  Serial.println("Start Check Tag Info : " + getTime());

  // Delete Expired Tag From Ignore Tag List
  for (int i = 0; i < 10; i++) {
    if (lastTag[i].dt > 0) {
      if ((mil - lastTag[i].dt) > IgnoreInterval * 1000)
        lastTag[i] = {"", 0};
    }
  }
  // Check if Tag exists in ignore tag list
  for (int i = 0; i < 10; i++) {
    if (lastTag[i].ID == Tag) {
      Serial.println(Tag + " Exists at : " + i);
      return;
    }
  }
  // Add Tag in ignore list
  for (int i = 0; i < 10; i++) {
    if (lastTag[i].dt == 0) {
      lastTag[i] = {Tag, mil};
      break;
    }
  }

  // Read Personnel Database File
  myFile = SD.open("Tag.txt", O_READ);
  String Conf;
  if (myFile) {

    while (myFile.available()) {
      int ls = myFile.read();
      if (ls == 13) {
        if (Conf.substring(0, 8) == Tag)
        {
          BLtmr = mil;
          Serial.println("Tag Found . . . ");
          Serial.println(Conf);
          LCDData = true;
          lcd.clear();
          lcd.setCursor(0, 0);
          lcd.print("    WELCOME     ");
          lcd.setCursor(0, 1);
          lcd.print(Conf.substring(9));
          Beep(1);
          myFile.close();
          WriteLog(Tag, Conf.substring(9));
          break;
        }
        Conf = "";
      }
      else
      {
        if (ls != 10) {
          Conf += char(ls);
        }
      }

    }
  }
  else {
    Serial.println("File Not Found . . . ");
    lcd.setCursor(0, 1);
    lcd.print("  Invalid File  ");
  }
  if (Conf == "") {
    lcd.setCursor(0, 0);
    lcd.print(getTimeMin());
    lcd.setCursor(0, 1);
    lcd.print("  Invalid Card  ");
    Beep(0);
  }
  Serial.println(getTime());
  myFile.close();
}

//====================================================================
//==================== I/O Func ======================================
String GetDirName() {
  DateTime nw = RTC.now();
  if (nw.month() < 10)
    return "/" + String(nw.year()) + "0" + String(nw.month());
  else
    return "/" + String(nw.year()) + String(nw.month());
}

String GetDelDirName() {
  DateTime nw = RTC.now();
  if (nw.day() != 1 | nw.hour() != 0 | nw.minute() != 0) {
    Serial.println("NOt Delete Time");
    return "";
  }

  if (nw.month() <= deleteInterval + 1)
  {
    int y = nw.year() - 1;
    int m = nw.month() + 12 - (deleteInterval + 1);
    if (m < 10)
      return "/" + String(y) + "0" + String(m);
    else
      return "/" + String(y) + String(m);
  }
  else
  {
    int y = nw.year();
    int m = nw.month() - (deleteInterval + 1);
    if (m < 10)
      return "/" + String(y) + "0" + String(m);
    else
      return "/" + String(y) + String(m);

  }
}

String GetFileName() {
  DateTime now = RTC.now();
  if (now.day() < 10)
    return GetDirName() + "/0" + String(now.day()) + ".txt";
  else
    return GetDirName() + "/" + String(now.day()) + ".txt";
}

String GetLink(String Tag, String Name) {
  DateTime now = RTC.now();
  return "<a title='مشاهده گزارش کامل ماه' target='_blank' href='log.htm?file=" + GetDirName().substring(1) + "/" + Tag + "'>" + Name + "</a>";
}

//====================================================================
String GetSyslogName() {
  return GetDirName() + "/SysLog.txt";
}


//====================================================================
String GetTagFileName(String Tag) {
  return GetDirName() + "/" + Tag + ".txt";
}


//====================================================================
//==================== Log Func ======================================
//====================================================================
void WriteLog(String Tag, String Name)
{
  if (LogData) {
    char dr[21];
    (GetDirName()).toCharArray(dr, 8);
    Serial.println(dr);
    if (!SD.exists(dr)) {
      SD.mkdir(dr);
      Serial.println("Directory Created");
    }
    GetFileName().toCharArray(dr, 15);
    if (!SD.exists(dr)) {
      myFile = SD.open(dr,  O_CREAT | O_WRITE);
      Serial.println("File Created");
      myFile.println("شماره ریدر,شماره کارت,نام صاحب کارت,زمان تردد");
      myFile.println(String(MyID) + "," + Tag + "," + GetLink(Tag, Name) + "," + getTime());
      myFile.close();
    }
    else
    {
      Serial.println("File Exists");
      myFile = SD.open(dr,  O_CREAT | O_WRITE);
      myFile.println(String(MyID) + "," + Tag + "," + GetLink(Tag, Name) + "," + getTime());
      myFile.close();
    }
    Serial.println("Daily Log File Complete");

    GetTagFileName(Tag).toCharArray(dr, 21);
    if (!SD.exists(dr)) {
      myFile = SD.open(dr,  O_CREAT | O_WRITE);
      Serial.println("File Created");
      myFile.println("شماره ریدر,شماره کارت,نام صاحب کارت,زمان تردد");
      myFile.println(String(MyID) + "," + Tag + "," + Name + "," + getTime());
      myFile.close();
    }
    else
    {
      Serial.println("Tag File Exists");
      myFile = SD.open(dr,  O_CREAT | O_WRITE);
      myFile.println(String(MyID) + "," + Tag + "," + Name + "," + getTime());
      myFile.close();
    }
  }
  Serial.println("Log Write Complete");

  if (mil - TCPLast >= 3600000) TCPTry = 0;
  if (SendTCP & TCPTry < 3) {
    if (cln.connect(ServerIP, ServerPort)) {
      Serial.println("Start Sending Log To Server");
      cln.println(String(MyID) + "," + Tag + "," + Name + "," + getTime());
      delay(1);
      cln.stop();
      Serial.println("Log Send Compete");
    }
    else
    {
      TCPTry += 1;
      Serial.print("Connection Not Complete");
      Serial.println(". Retry : " + String(TCPTry));
    }
    TCPLast = mil;
  }
}

void LoadConfig() {
  myFile = SD.open("Config.txt");
  if (myFile) {
    Serial.println("Reading Config File ...");
    String Conf;
    // read from the file until there's nothing else in it:
    int cnt = 1;
    while (myFile.available()) {
      int ls = myFile.read();
      // read Data While Finding Enter (Char 13)
      if (ls == 13) {
        switch (cnt) {
          case 1:
            {
              int i1 = getValue(Conf, '.', 0).toInt();
              int i2 = getValue(Conf, '.', 1).toInt();
              int i3 = getValue(Conf, '.', 2).toInt();
              int i4 = getValue(Conf, '.', 3).toInt();
              IP = IPAddress(i1, i2, i3, i4);
              Serial.println("IP : " + Conf);
              break;
            }
          case 2:
            {
              int i1 = getValue(Conf, '.', 0).toInt();
              int i2 = getValue(Conf, '.', 1).toInt();
              int i3 = getValue(Conf, '.', 2).toInt();
              int i4 = getValue(Conf, '.', 3).toInt();
              subnet = IPAddress(i1, i2, i3, i4);
              Serial.println("SubNet : " + subnet);
              break;
            }
          case 3:
            {
              int i1 = getValue(Conf, '.', 0).toInt();
              int i2 = getValue(Conf, '.', 1).toInt();
              int i3 = getValue(Conf, '.', 2).toInt();
              int i4 = getValue(Conf, '.', 3).toInt();
              gateway = IPAddress(i1, i2, i3, i4);
              Ethernet.begin(mac, IP, gateway, subnet);
              W5100.setRetransmissionTime(0x07D0);
              W5100.setRetransmissionCount(3);
              server.begin();
              Serial.println("GetWay : " + Conf);
              break;
            }
          case 4:
            { MyID = Conf.toInt();
              Serial.println("MyID : " + Conf);
              break;
            }
          case 5:
            { int i1 = getValue(Conf, '.', 0).toInt();
              int i2 = getValue(Conf, '.', 1).toInt();
              int i3 = getValue(Conf, '.', 2).toInt();
              int i4 = getValue(Conf, '.', 3).toInt();
              ServerIP = IPAddress(i1, i2, i3, i4);
              Serial.println("Server IP : " + Conf);
              break;
            }
          case 6:
            { ServerPort = Conf.toInt();
              Serial.println("ServerPort : " + Conf);
              //UDP.begin(ServerPort);
              //  cln.connect(ServerIP,ServerPort);
              break;
            }

          case 7:
            { IgnoreInterval = Conf.toInt();
              Serial.println("IgnoreInterval : " + Conf);
              break;
            }
          case 8:
            { deleteInterval = Conf.toInt();
              Serial.println("Delete Interval : " + Conf + " Days");
              break;
            }
          case 9:
            { LogData = Conf.toInt() == 1 ? true : false;
              Serial.println("Log Traffic : " + String(LogData));
              break;
            }
          case 10:
            { SendTCP = Conf.toInt() == 1 ? true : false;
              Serial.println("TCP Send Log : " + String(SendTCP));
              break;
            }
          case 11:
            { Bp = Conf.toInt() == 1 ? true : false;
              Serial.println("Beep : " + String(Bp));
              break;
            }
        }
        cnt += 1;
        Conf = "";
      }
      else if (ls != 10)
        Conf += char(ls);
    }

  }
  // close the file:
  myFile.close();
  Serial.println("Configuration Complete");
}

