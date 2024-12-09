# decrypt_app.py

import streamlit as st
from cryptography.fernet import Fernet


def decrypt_string(s: str, key: str) -> str:
    f = Fernet(key.encode())
    return f.decrypt(s.encode()).decode()


def main():
    st.set_page_config(page_title="🎄 Święta 2024", layout="centered")
    st.title("🎁 Komu robię prezent?")
    st.markdown(
        """
    Aby odkryć, komu robisz prezent, wprowadź zaszyfrowaną wiadomość oraz klucz do odszyfrowania.
    
    Znajdziesz je w pliku tekstowym, który otrzymałeś/aś. 
    
    Ho ho ho! 🎅🏼🎄
    
    
    """
    )

    # Input for Encrypted Message
    encrypted_message = st.text_input("Wpisz zaszyfrowaną wiadomość:")

    # Input for Decryption Key
    decryption_key = st.text_input("Wpisz klucz do odszyfrowania:")

    # Decrypt Button
    if st.button("👀 Odszyfruj"):
        if not encrypted_message:
            st.error("Musisz wprowadzić zaszyfrowaną wiadomość.")
        elif not decryption_key:
            st.error("Musisz wprowadzić klucz do odszyfrowania.")
        else:
            try:
                decrypted_message = decrypt_string(encrypted_message, decryption_key)
                st.success("✅ Odszyfrowano pomyślnie!")
                st.info("Wylosowana osoba: " + decrypted_message)
            except Exception as e:
                st.error(
                    f"⚠️ Coś poszło nie tak... Sprawdź, czy wprowadziłeś/aś poprawne dane. {e}"
                )


if __name__ == "__main__":
    main()
