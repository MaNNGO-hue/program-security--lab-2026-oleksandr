# Архітектурний опис системи SafeVault (ISO/IEC/IEEE 42010:2022)
* **Зацікавлені сторони:** відправник секрету, отримувач секрету, аудитор безпеки.
* **Компоненти системи:** API Layer (`controller` — валідація DTO та Rate Limiting до 20 запитів/хв), Service Layer (`service` — транзакційні переходи станів), Cryptography Component (`crypto` — AES-256-GCM, SHA-256, CSPRNG 256 біт), Persistence Layer (`repository` — PostgreSQL із песимістичним блокуванням), Cleanup Scheduler (`scheduler` — очищення прострочених нотаток кожні 30 с).
* **Зовнішні інтерфейси:** REST API (`POST /api/v1/notes`, `GET /api/v1/notes/{accessToken}`, `DELETE /api/v1/notes/{revokeToken}`) по HTTPS.
