# Sigma → Wazuh avtomatik konvertasiya

Sigma YAML qaydalarını Wazuh `local_rules.xml` formatına çevirir.

## Tələb

- Python 3.9+
- `pip install -r requirements.txt`

## İstifadə

```bash
cd sigma/scripts
pip install -r requirements.txt

# Default: sigma/wazuh/local_rules.xml yaradır
python convert_sigma_to_wazuh.py

# Öz yollarınız
python convert_sigma_to_wazuh.py --sigma-dir ../ --output ../wazuh/local_rules.xml
```

## Wazuh manager-ə deploy

```bash
# Linux Wazuh manager-də
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-logtest
```

Və ya birbaşa manager-də skripti işlədin:

```bash
git clone https://github.com/hackatonteam96-eng/Autograph
cd Autograph/sigma/scripts
pip install -r requirements.txt
python convert_sigma_to_wazuh.py --output /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

## Sigma yeniləndikdə

```bash
git pull
python convert_sigma_to_wazuh.py --output /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Repo-da yalnız **Sigma YAML** qalır; XML manager-də avtomatik yaranır.

## Qeydlər

- `kerberoasting.yml`, `asreproasting.yml`, `golden-ticket.yml`, `brute-force.yml` skip olunur (suite qovluqlarında eyni qaydalar var)
- Correlation qaydalar (`timeframe`, `count_distinct`) child + parent Wazuh qaydası kimi çevrilir
- `1 of selection_*` və `1 of filter_*` OR məntiqi dəstəklənir
- Çıxan rule ID-lər sigma `id` sahəsindən stabil hash ilə yaranır (100000+)

## Test

Wazuh manager-də real 4625 və ya 4769 event JSON-u ilə `wazuh-logtest` işlədin.
