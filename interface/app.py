import streamlit as st
from analyzer import rate_site

st.set_page_config(page_title="Verificador de Site", page_icon="🌐")
st.title("🔍 Verificador de Legitimidade de Sites")
st.write("Digite a URL de um site para obter um feedback.")

url_input = st.text_input("URL do site:", placeholder="https://exemplo.com")

if url_input:
    classification, reasons, color = rate_site(url_input)
    st.markdown(
        f"<h2 style='color:{color};'>{classification}</h2>", unsafe_allow_html=True
    )
    if reasons:
        st.markdown("### Motivos:")
        for m in reasons:
            st.write(f"- {m}")
