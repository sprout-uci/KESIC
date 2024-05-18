# KESIC
## IoT Server
Synchronization of IoT devices: Kerberos-IoT/KerberosProject/SynchronizationManager.py

Granting tickets to clients: app.py

Execution command: python3 app.py
## IoT Device
Kerberos-IoT/lpcxpresso55s69_device_attestation_s, Kerberos-IoT/lpcxpresso55s69_device_attestation_ns

Change the values of  **SERVER_ADDRESS_FIRST**, **SERVER_ADDRESS_SECOND**, **SERVER_ADDRESS_THIRD**, **SERVER_ADDRESS_FOURTH** in Kerberos-IoT/lpcxpresso55s69_device_attestation_ns/source/wlan_qcom.c to match the address of IS 

## Client Application: 
Kerberos-IoT/KerberosProject/Client.py

Execution command: python3 Client.py username device_id

Configure these values using **usernames** and **device_ids** variables in Kerberos-IoT/KerberosProject/Constants.py

Also need to change values of **url** (line 30) and **device_ip** (line 71) variables in Kerberos-IoT/KerberosProject/Client.py
