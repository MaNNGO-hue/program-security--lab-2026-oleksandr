# Політика розробки проєкту SafeVault
* **Стек технологій:** Java 21 (LTS), Spring Boot 3.x, Maven, PostgreSQL 16, JUnit 5.
* **Стандарти кодування:** пакетна структура (`controller`, `service`, `crypto`, `repository`, `model`, `dto`), класи у `PascalCase`, методи у `camelCase`, константи у `UPPER_SNAKE_CASE`.
* **Правила безпеки:** заборонено зберігати паролі та ключі шифрування в репозиторії (використовуються змінні середовища `SAFEVAULT_MASTER_KEY` та SSL/TLS для підключення до БД); відповіді API не розкривають stack trace.
* **Робота з Git:** основна гілка `main`, префікси комітів `[INIT]`, `[DOCS]`, `[FEAT]`, `[FIX]`, `[TEST]`.
