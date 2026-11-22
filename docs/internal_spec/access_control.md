# Модель керування доступом системи SafeVault (ЛР №5)

## 1. Суб'єкти, ресурси та захищені операції
* **Суб'єкти доступу:** отримувач нотатки за токеном, автентифікований користувач (`ROLE_USER`), власник нотатки (`ownerId`), адміністратор безпеки (`ROLE_ADMIN`).
* **Ресурси (об'єкти) доступу:** конфіденційна нотатка (`SecretNote`), журнал аудиту (`AuditLog`).
* **Захищені операції:** створення нотатки (`CREATE_NOTE`), читання нотатки (`READ_NOTE`), дострокове відкликання нотатки (`REVOKE_NOTE`), перегляд журналу аудиту (`VIEW_AUDIT_LOGS`).

## 2. Обрана модель доступу (змішана RBAC + ABAC / Ownership)
Для вебсервісу **SafeVault** застосовано **змішану модель керування доступом**:
* **RBAC (рольовий підхід):** розмежовує системні права між ролями `ROLE_USER` та `ROLE_ADMIN` (перегляд журналу аудиту доступний лише адміністратору).
* **ABAC + контроль власника (Ownership):** контролює операції над конкретною нотаткою за атрибутами суб'єкта (`userId`, `mfaAuthenticated`), об'єкта (`ownerId`, `status`, `remainingViews`, `expiresAt`, `requiresMfa`, `accessTokenHash`) та поточного часу UTC.

## 3. Матриця правил доступу

| Операція | Умова дозволу (Allow) | Умова відмови (Deny) |
| :--- | :--- | :--- |
| `CREATE_NOTE` | Користувач автентифікований (`userId != null`) | Анонімний запит (`401 Unauthorized`) |
| `READ_NOTE` | Збіг `accessTokenHash`, `status == ACTIVE`, `remainingViews > 0`, `now < expiresAt`, та підтверджено МФА (якщо `requiresMfa == true`) | Невірний токен або відсутнє МФА (`403 Forbidden`); нотатка знищена чи прострочена (`410 Gone`) |
| `REVOKE_NOTE` | `status == ACTIVE` та `subject.userId == note.ownerId` | Спроба відкликати чужу нотатку (`403 Forbidden`) |
| `VIEW_AUDIT_LOGS` | `subject.role == ROLE_ADMIN` та `subject.mfaAuthenticated == true` | Роль `ROLE_USER` або сесія адміністратора без МФА (`403 Forbidden`) |