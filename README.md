# One Time Password (OTP) Based on Advanced Encrypted Standard (AES) and Linear Congruential Generator(LCG)

# 1. Topic overview

## Application context
User authentication in e-commerce websites.

| **Subject** | **Description** |
| --- | --- |
| Protected Assets | User's credentials and payment information |
| Related-Party | Users: receive OTP to verify activities such as logging in, ordering, changing personal information, payment, etc. <br />OTP service providers: provide OTP codes to users when requested. <br />Banks: provide OTP authentication services to users when making online payment transactions. |
| Security Goals | Prevent unauthorized access to user's accounts |
  
## Abstract
In e-commerce, it is important to protect user credentials in order to prevent fraudulent activities that can result in the theft of personal information and money. Hear are some ways to protect user credentials include:
- Use encryption to protect user credentials during transmission and storage.
- Use network security techniques such as firewalls, intrusion detection, and denial of service (DDoS) prevention to prevent outside attacks.
- Use two-factor authentication (2FA) or multi-factor authentication (MFA) solutions to protect accounts from credential theft attacks. These authentication methods include OTP, smart card, and fingerprint identification.
- Provide security keys to users to protect their login information.

# 2. Solution
In this study, we choose two-factor authentication (2FA) to solve the problem mentioned above. Among OTP, smart card, FaceID, and fingerprint identification, OTP is a simple yet effective way as OTP can be generated using a variety of methods, such as through a mobile app, via SMS text message. <br/>
Cases where OTP is used:
- Verify account when registering for a new purchase.
- Verify when conducting transactions on e-commerce websites.
- Verify when changing personal information or password.
- Verify when adding, editing or deleting payment information.
- Verify when requesting password recovery.
- Verify when making transactions with large amounts of money.
- Verify when using security services on e-commerce websites.
- Verify when logging into an account on an e-commerce website from a new device.
- Verify when performing important activities on e-commerce websites.
- Verify when using account management functions on e-commerce websites.

Within the scope of the project, we choose case **Verify when logging into an account on an e-commerce website from a new device** to implement. 

# 3. Implement
In this study, an OTP was generated by utilizing a combination of the user's login, phone number, and time of access. The plaintext was encrypted using Advanced Encryption Standard (AES) before a Linear Congruential Generator (LCG) randomly selected 6 characters. This proposed method of OTP generation offers added protection to user accounts. The figure below show how this proposed method work.

<p align="center">
  <img src="https://user-images.githubusercontent.com/91709484/226950629-447f4951-4ad7-4201-ba9b-305d284bc74c.png" alt="Flowchart of Proposed Method"/>
</p>
<p align="center" dir="auto">
Figure 1. Flowchart of Proposed Method
</p>

<p align="center">
  <img src="https://user-images.githubusercontent.com/91709484/226949108-ca00038b-3084-4ea6-a071-932d4e7e798a.jpg" alt=""/>
</p>
<p align="center" dir="auto">
Figure 2. Log in using OTP
</p>

## Deploy plan
| **Target** | **Plan** |
| :--- | :--- |
| User Registration | The user registers with the system by providing their email address and phone number. |
| OTP Generation | When the user attempts to log in, the system generates a new OTP using the AES and LCG algorithm. |
| OTP Transmission | The system sends the OTP to the user's registered email and phone number. |
| User Input | The user enters the received OTP in the login screen and clicks the login button. |
| OTP Verification | The system decrypts the received OTP using the user's secret key and verifies that it matches the generated OTP. If the OTPs match, the user is authenticated and allowed to access the system. |
| OTP Verification | The system decrypts the received OTP using the user's secret key and verifies that it matches the generated OTP. If the OTPs match, the user is authenticated and allowed to access the system. |


## Tools and resources
| **Tools and resources** | **Description** |
| :--- | :--- |
| PyCrypto | Library |
| Python | Programming Language |
|MySQL  | Database |
| Flask | Python Framework |

## Task chart
| Task | Phan Thị Hồng Nhung (21521250) | Đoàn Hải Đăng (21520679) | Lê Thanh Tuấn (21520518) |
| :--- | :---: | :---: | :---: |
| Identifying the problem and proposing solution | x | x | x |
| Design | x | x |  |
| Database |  | x | x |
| Implement and Test | x |  | x |
| Presentation | x |  |  |
