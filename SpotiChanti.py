import spotipy
from spotipy.oauth2 import SpotifyOAuth
import pandas as pd
import streamlit as st
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px

st.set_page_config(page_title="Firma Digital", layout="wide", page_icon="🔐")
st.markdown("<h1 style='text-align: center;'>Bienvenido a tu análisis de Spotify</h1>", unsafe_allow_html=True)

# Configura tus credenciales
sp = spotipy.Spotify(auth_manager=SpotifyOAuth(
    client_id="8459883cb198419cab568ce24fff55db",
    client_secret="0c244581e7774493981a6bb617afb95c",
    redirect_uri="http://127.0.0.1:8888/callback",
    scope="user-read-private user-read-email user-top-read user-read-recently-played user-library-read"
))

# Obtener las 50 canciones recientes
results = sp.current_user_recently_played(limit=50)

# Procesar los datos
data = []
for item in results['items']:
    track = item['track']
    played_at = item['played_at']
    duration_ms = track['duration_ms']
    duration_min = duration_ms / 60000
    data.append({
        'Fecha y Hora': played_at,
        'Canción': track['name'],
        'Artista': track['artists'][0]['name'],
        'Duración (min)': round(duration_min, 2),
        'Popularidad': track['popularity'],
        'ID': track['id'],
        'URI': track['uri'],
    })
# Guardar en CSV
df = pd.DataFrame(data)
df

# Cantidad de canciones por artista
artista_counts = df['Artista'].value_counts()

# Crear un gráfico de pie con plotlty
fig = px.pie(artista_counts, values = artista_counts.values, names=artista_counts.index, title='Distribución de Canciones Recientes')

st.plotly_chart(fig, use_container_width=True)