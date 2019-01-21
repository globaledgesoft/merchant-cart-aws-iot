### Introduction
This is Merchant Cart demo of Music Festival for Inventory Management

### Pre-requisites
Create EC2 instance and enable port 8655 in security group to run your application in EC2.

### Setup in EC2
To install NodeJS :
```
	$ curl -sL https://deb.nodesource.com/setup_9.x | sudo -E bash –
	$ sudo apt-get install nodejs
```
To install Postgres :
```
    $ sudo apt-get update
    $ sudo apt-get install postgresql postgresql-contrib
```
Install NodeJS process Manager
```
$ npm install pm2 -g
```
### Adding application to EC2 instance:
Copy **webapp** folder to your EC2 instance.
```
 $ scp -i <pem file> -r webapp <EC2-instance-url>
```
## Run the application
Goto following folder: webapp 
Run the server in EC2 instance with : pm2 start

### Setting up the  Quectel EVB:
##### Getting started

The board comes with a firmware pre-installed. The firmware version can be 2.0 or 3.0. This firmware invokes application entry point on boot. This entry point is quectel_task_entry in case of 2.0 firmware. Application developers can develop applications for BG96 using SDK (2.0/3.0). The current version of this application only supports Quectel SDK 2.0.

Application development can be done on Windows 7 host machine. Applications can be cross-compiled for BG96 using ARM DS5 licence.

Pls download SDK from https://www.quectel.com/product/bg96.htm
#### Compiler installation

Please refer docs\Quectel_BG96-QuecOpen_Application_Note_V1.0_Preliminary_20180502.pdf (section 3) for information regarding DS5 ARM compiler download and installation. Based on duration needed to complete your project you can choose to use 1 month free trial version. This setup is for working with Quectel SDK 2.0
#### Driver installation

Please refer document docs\Quectel_BG96_Windows_USB_Driver_Installation_Guide_V1.0.pdf for information on downloading and installation of USB drivers on Windows 7 machines.

Please carefully follow the instructions given in the document. You'll need Quectel BG96 board to begin USB driver installation

You should be able to see DM, AT, Modem ports in the 'Windows Device Manager' once USB drivers are successfully installed.

### Building and Flashing application program

Building and flashing applications is fairly straight-forward. All the examples/applications are available under src\example folder

##### Building:-

1.Open command prompt.
2.Navigate to folder with SDK 2.0 (Quectel_BG96_QuecOpen_SDK_Package_V2.1.0). You'll find the makefile build_oem_example.bat
3.Replace build_oem_example.bat with build_oem_example.bat.
Before application building, must set a correct path for the compiler tools in the build_oem_example.bat:

```
set TOOL_PATH_ROOT=C:\compile_tools
set TOOLCHAIN_PATH=%TOOL_PATH_ROOT%\ARM_Compiler_5\bin
set LM_LICENSE_FILE=%TOOL_PATH_ROOT%\license.dat
```
4. run build_oem_example.bat sub_pub

This command will automatically build all the .c files in the directory src/example/sub_pub. Generates a .bin file called example_sub_pub.bin. In addition it also generates a file called oem_app_path.ini. These files are generated under main SDK folder Quectel_BG96_QuecOpen_SDK_Package_V2.1.0\bin

#### Flashing:-
1. Connect the board to host machine
2. Open QEFS_Explorer.exe under main SDK folder Quectel_BG96_QuecOpen_SDK_Package_V2.1.0\tools
3. Choose the board displayed under File->Device and click on the 'search' button
4. From among the directories listed click on /datatx folder
5. Copy example_sub_pub.bin, oem_app_path.ini into this (/datatx) folder
6. Please, change the required network configuration in the config file: demo3.cfg
You can specify apn, username and password to connect to your network in demo3.cfg (in the format apn|username|password). If apn, username and password are not applicable  you need not copy this file
```
apn – Access Point Name of the carrier used 
username – Username for the APN if any
password – Password for the APN if any
```
and copy this file into /datatx.
7. copy QCA4020_MUSIC_FTV.cert.pem to /datatx.
8. copy QCA4020_MUSIC_FTV.cert.private to /datatx.
9. Reset the board
### Make GPIO connections 
Place the sensor mat on the Merch Cart 
Connect the wires to the Quectel EVB board to following gpio pins:
| Sensor No.| GPIO Pin Name  | GPIO Unit no.  |
| :---:   | :-: | :-: |
| Sensor_1 | GPIO_79 | J0202|
| Sensor_1 | GPIO_78 | J0202 |
| Sensor_1 | GPIO_77 | J0202 |
| Sensor_1 | GPIO_76 | J0202 |
| Sensor_1 | GPIO2 | J0203 |

Note:- Connect sensor mat GND to Quectel EVB board GND (J0202 GND) and VCC to VDD_1V8 (J0202 pin2)
### Running Application:-
Connect the power cable to the Quectel EVB. Make sure the power switch is in OFF position.

Connect the serial to USB cable to “Com Debug” to see Quectel EVB logs.
Power on the Quectel EVB board This is a two-step process, 
1. Flip the switch to ON position.
2. Press the power button next to the Micro USB connector 

You will see Green LED turn ON. This means that the Board is ON 
POWER – Red (Constant) 
STATUS – Green (Constant) 
NET_STATUS – Blue (Blinking) 


Launch Chrome Browser on any host PC and navigate to the following link: http://ip_address_of_AWS_instance:8655 
### Troubleshoot : 
Mobile Wireless Data connectivity
##### SIM Registration
Please use the following AT cmds after downloading the binary to test SIM registration. In case data connectivity does not work automatically we may need to fall back to GSM/GPRS mode. Use AT port for AT CMDs.
First let's check if the SIM is registered. Use following AT commands:
```
1. AT+CPIN?

2. AT+CSQ

3. AT+CREG?

4. AT+CGREG?

5. AT+CVERSION
```
CSQ needs to be more than 10
CGREG and CREG should have 0,1 (0,1 means registered to the network)
##### Fall back to GSM/GPRS mode
Please run following AT CMDs:
```
at+qcfg="nwscanmode", 1

at+qcfg="nwscanseq", 1
```
This will default to GSM mode for data connectivity and then hopefully succeed in making data call. Please re-check sim registration using above AT CMDs in case data call doesn't succeed 

