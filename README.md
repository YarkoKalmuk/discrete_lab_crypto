**Лабораторна робота з дискретної математики по RSA кодуванню та хешуванні**
Виконали Кальмук Ярополк та Головін Максим

# Працює наша програма таким чином:
1) При запуску програми спочатку запускається сервер. На стороні сервера створюються публічні та приватні ключі випадковим чином за допомогою функції generate_keys(). Для цього створюються прості p, q у межах від 1000 до 5000 (можна змінити). Вираховується число n=p*q, phi(n)=(p-1)(q-1) та e таке, що 3 <= e <= phi(n). За допомогою функції mod_inverse() шукаєм секретний ключ d, який повинен задовільняти: d*e = 1 (mod phi(n)).

2) Запускаєм файл client.py з іншого терміналу, вибираємо нікнейм на свій вибір (без пробілів, спеціальних знаків окрім "_"). На стороні клієнта створюються публічні та приватні ключі за таким самим принципом що у сервера.

3) Обмін ключів. Сервер бачить клієнта та записує його публічні ключі, ім'я та іншу інформацію. Після цього сервер передає клієнту свої публічні ключі як (n, e). Клієнт їх зберігає. Пізніше можна доєднувати інших клієнтів через інший термінал, змінивши їхнє ім'я при цьому. При доєднанні клієнтів сервер сповіщає всіх інших користувачів, що новий клієнт доєднався.

4) Щоб зі сторони клієнта відіслати повідомлення іншому клієнту, треба написати: "To @alice: {message}" (cлово "To " можна опустити, головне, щоб був символ @ і після нього ім'я та двокрапки. Просто так буде краща читабельність.) Звісно, це повідомлення шифрується і дешифрується, як саме я опишу згодом.

5) Тільки той, кому було віправлене повідомлення, бачить його вміст у себе в терміналі. Це показано так: "From @yaropolk: {message}".

###### Сам алгоритм кодування та декодування використовуючи блокове кодування RSA:
Ось як відбувається загальний процес передачі повідомлень:
1. клієнт_1 хоче відіслати клієнту_2 повідомлення message. Для цього він шифрує повідомлення публ ключами сервера, та передає його на сервер.
2. Сервер розкодовує повідомлення, бачить ім'я отримувача.
3. Сервер кодує повідомлення публічними ключами клієнта_2 та відправляє його йому.
4. Клієнт_2 розкодовує своїм приватним ключем повідомлення. Дістає вже читабельний message.

*Також сервер має функцію broadcast(). Для цього він проходиться по кожному клієнту і шифрує заданий message, починаючи з пункту 3.

#### 1. Кодування:
Щоб закодувати повідомлення message, треба:
1) Перетворити повідомлення у вигляд рядка з ascii цифр, при цьому доставити нулі спереду кожного символа за потреби, щоб кожен символ мав довжину 3 цифри.
("h" -> "104", "D" -> "068", "hi" -> "104105")

2) Розбити на блоки. Для цього треба знати публічний ключ n отримувача. Це робиться для того, щоб будь-яке довге повідомлення можна було розшифрувати, бо якщо напряму шифрувати рядок з цифр "1043674319813", треба, щоб n було більше за це число. Отже, якщо довжина ключа n отримувача становить 6, то максимальна довжина блоків - 5. Якщо ж n=8, то макс довжина блоків - 7. Розбиваємо рядок цифр на блоки з цією довжиною. Останній блок може не збігатись розміром з іншими блоками, і це нормально. Для цього запамятовуєм його довжину last_block_len, це допоможе у декодуванні.

3) Кожен блок m шифруєм і обраховуєм як m^e (mod n), де e та n - публічні ключі клієнта. Далі важливо: треба зробити всі закодовані блоки однакової довжини, щоб отримувач правильно розбив повідомлення на них. Для цього кожен блок має бути довжини len(n), а якщо ні - доповнити нулями спереду блоку. len(n) саме тому, що бувають випадки, коли нехай довжина ключа n = 5, довжина блоку = 4, але після підняття до степеня e за модулем n довжина блоку стала 5, і клієнт, щоб отримати цей блок повинен розбити по п'ять цифр. Інших випадків бути не може.

4) Відсилаєм отримувачу/серверу повідомлення "hash|encrypted|last_block_len". Про hash скажем згодом.

#### 2. Декодування:
На вхід прийшов message, що являє собою: hash|encrypted_msg|last_block_len. Дістаєм encrypted_message та last_block_len

1) Розбиваєм один рядок цифр на блоки довжиною len(n) кожне.

2) Для кожного блоку виконуєм операцію: C^d (mod n), де С - кожен блок, d - наш секретний ключ, n - наш публічний ключ.

3) Далі проходимся по кожному блоку і додаєм нулів на початок, щоб довжина була len(n)-1, окрім останнього блоку. Це робиться для того, щоб не втратити ascii символи, тобто нулі, коли ми будем об'єднювати блоки в рядок. Останній блок робим довжини last_block_len. Нам це важливо робити, щоб не додати забагато нулів. (при шифруванні останній блок може мати меншу довжину за інші, це було сказано)

4) Об'єднюємо блоки в одне велике число

5) Перетворюєм кожні три послідовні цифри на символи з ascii-таблиці. Повідомлення розкодовано.

Перевірка на цілісність:
Перед шифруванням повідомлення, обраховується його хеш модулем hashlib. Потім клієнт відсилає на сервер hash|encrypted_msg|last_block_len. Спочатку сервер розкодовує повідрмлення, і обраховує для нього новий хеш. Якщо хеші однакові, то все добре. Після цього сервер відправляє отримувачу теж hash|encrypted_msg|last_block_len. Коли отримувач розкодував повідомлення, він рахує для нього хеш та звіряє з наданим.


Розподіл роботи:
Кальмук Ярополк - створення публічних, приватних ключів сервера та клієнта, їхня передача, удосконалення rsa алгоритму використовуючи блоки, частина звіту, перевірка на цілісність повідомлення;
Головін Максим - реалізація передачі повідомлень між клієнтами та сервером, шифрування та дешифрування повідомленнь (база), частина звіту
