import streamlit as st
from analyzer import rate_site

st.set_page_config(page_title="Verificador de Site", page_icon="🌐")
st.title("🔍 Verificador de Legitimidade de Sites")
st.write("Digite a URL de um site para obter um feedback.")

url_input = st.text_input("URL do site:", placeholder="https://exemplo.com")

if url_input:
    classificacao, motivos, cor = rate_site(url_input)
    st.markdown(f"<h2 style='color:{cor};'>{classificacao}</h2>", unsafe_allow_html=True)
    if motivos:
        st.markdown("### Motivos:")
        for m in motivos:
            st.write(f"- {m}")