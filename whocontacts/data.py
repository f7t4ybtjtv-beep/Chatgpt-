"""Jeux de données embarqués (listes réduites, extensibles)."""
from __future__ import annotations

# Fournisseurs d'e-mail gratuits grand public (non exhaustif).
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "ymail.com",
    "hotmail.com", "hotmail.fr", "outlook.com", "outlook.fr", "live.com",
    "live.fr", "msn.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "protonmail.com", "proton.me", "pm.me", "gmx.com", "gmx.fr", "zoho.com",
    "mail.com", "yandex.com", "yandex.ru", "orange.fr", "wanadoo.fr",
    "free.fr", "laposte.net", "sfr.fr", "bbox.fr", "tutanota.com", "tuta.io",
}

# Domaines d'e-mail jetables / temporaires (signal de risque fort).
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "10minutemail.com",
    "tempmail.com", "temp-mail.org", "throwawaymail.com", "yopmail.com",
    "getnada.com", "trashmail.com", "sharklasers.com", "maildrop.cc",
    "dispostable.com", "fakeinbox.com", "mailnesia.com", "mohmal.com",
    "emailondeck.com", "spambog.com", "mytemp.email", "burnermail.io",
    "33mail.com", "mailcatch.com", "tempinbox.com", "moakt.com", "inboxkitten.com",
}

# Plateformes publiques pour la recherche de pseudo (URL avec {u}).
# Statut 200 => profil probable ; 404 => absent. À élargir au besoin.
USERNAME_SITES = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "TikTok": "https://www.tiktok.com/@{u}",
    "X/Twitter": "https://x.com/{u}",
    "Telegram": "https://t.me/{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "Medium": "https://medium.com/@{u}",
    "Keybase": "https://keybase.io/{u}",
    "Replit": "https://replit.com/@{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Dribbble": "https://dribbble.com/{u}",
    "Behance": "https://www.behance.net/{u}",
    "DevTo": "https://dev.to/{u}",
    "Vimeo": "https://vimeo.com/{u}",
    "About.me": "https://about.me/{u}",
}

# Indicatifs téléphoniques pays (préfixe E.164 -> (code ISO, nom FR)).
# Les plus longs d'abord lors de la correspondance.
PHONE_PREFIXES = {
    "1": ("US/CA", "Amérique du Nord (USA/Canada)"),
    "33": ("FR", "France"),
    "32": ("BE", "Belgique"),
    "41": ("CH", "Suisse"),
    "44": ("GB", "Royaume-Uni"),
    "49": ("DE", "Allemagne"),
    "34": ("ES", "Espagne"),
    "39": ("IT", "Italie"),
    "351": ("PT", "Portugal"),
    "31": ("NL", "Pays-Bas"),
    "352": ("LU", "Luxembourg"),
    "212": ("MA", "Maroc"),
    "213": ("DZ", "Algérie"),
    "216": ("TN", "Tunisie"),
    "221": ("SN", "Sénégal"),
    "225": ("CI", "Côte d'Ivoire"),
    "237": ("CM", "Cameroun"),
    "7": ("RU/KZ", "Russie / Kazakhstan"),
    "86": ("CN", "Chine"),
    "91": ("IN", "Inde"),
    "81": ("JP", "Japon"),
    "61": ("AU", "Australie"),
    "55": ("BR", "Brésil"),
    "52": ("MX", "Mexique"),
    "234": ("NG", "Nigeria"),
    "27": ("ZA", "Afrique du Sud"),
    "90": ("TR", "Turquie"),
    "971": ("AE", "Émirats arabes unis"),
    "972": ("IL", "Israël"),
    "380": ("UA", "Ukraine"),
}
