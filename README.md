# end2end-crypted-chatapp

**end2end-crypted-chatapp** to prosty komunikator tekstowy z graficznym interfejsem (GUI) oparty na Pythonie, umożliwiający bezpieczną komunikację użytkowników dzięki szyfrowaniu end-to-end. Obsługuje czaty indywidualne i grupowe oraz przesyłanie plików.

## Funkcje

- **Szyfrowanie end-to-end**: Każda wiadomość i plik są szyfrowane indywidualnym kluczem AES, a wymiana kluczy odbywa się z wykorzystaniem RSA.
- **Komunikacja 1:1 i grupowa**: Możliwość czatowania prywatnie oraz w grupach.
- **Przesyłanie plików**: Wysyłanie plików do użytkowników i grup, z podpisem cyfrowym.
- **GUI**: Intuicyjny interfejs graficzny oparty na Tkinter.
- **Lista użytkowników i grup**: Dynamiczne pobieranie listy zalogowanych użytkowników i grup.

## Wymagania

- Python 3.8 lub nowszy
- Biblioteki: `cryptography`, `tkinter` (w standardzie Pythona), `secrets`

Instalację zależności można wykonać przez:
```bash
pip install cryptography
```

## Uruchomienie

1. **Uruchom serwer:**

   W jednym terminalu uruchom:
   ```bash
   python server.py
   ```
   Domyślnie serwer nasłuchuje na `127.0.0.1:8000`.

2. **Uruchom klienta:**

   W osobnych terminalach uruchom tyle instancji klienta, ile chcesz użytkowników:
   ```bash
   python client.py
   ```
   W GUI wpisz nazwę użytkownika i kliknij "Connect".

## Architektura i bezpieczeństwo

- Wymiana kluczy odbywa się przy pomocy RSA (każdy użytkownik generuje własną parę kluczy).
- Komunikacja szyfrowana jest symetrycznym kluczem AES-GCM, który jest wymieniany za pomocą RSA.
- Wiadomości oraz pliki są podpisywane cyfrowo.
- Serwer pośredniczy w przekazywaniu wiadomości, ale nie ma dostępu do treści (zero-knowledge).

## Główne pliki

- `server.py` – Serwer czatu obsługujący klientów, grupy i przekazujący zaszyfrowane wiadomości.
- `client.py` – Aplikacja kliencka z GUI umożliwiająca rozmowę, przesyłanie plików i zarządzanie grupami.

## Zastrzeżenia

- Projekt ma charakter edukacyjny – nie był testowany pod kątem produkcyjnego bezpieczeństwa.
- Brak mechanizmu trwałego przechowywania wiadomości (wszystko jest w pamięci RAM).

## Autor

- [przemyslawbryzek](https://github.com/przemyslawbryzek)
