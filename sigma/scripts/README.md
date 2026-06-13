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

## Avtomatik deploy (cron)

Wazuh manager-də bir dəfə:

```bash
sudo apt install -y python3-yaml git   # və ya: python3.10-venv
sudo git clone -b sigma https://github.com/hackatonteam96-eng/Autograph.git /opt/Autograph
cd /opt/Autograph/sigma/scripts
sudo bash install-cron.sh
sudo /usr/local/bin/authgraph-deploy-wazuh.sh
```

| Nə | Dəyər |
|----|-------|
| Schedule | Hər gün **02:00** (default) |
| Skript | `/usr/local/bin/authgraph-deploy-wazuh.sh` |
| Log | `/var/log/authgraph-wazuh-deploy.log` |

Manual test: `sudo /usr/local/bin/authgraph-deploy-wazuh.sh`

Hər 6 saat: `sudo CRON_SCHEDULE='0 */6 * * *' bash install-cron.sh`

## Qeydlər

- `kerberoasting.yml`, `asreproasting.yml`, `golden-ticket.yml`, `brute-force.yml` skip olunur (suite qovluqlarında eyni qaydalar var)
- Correlation qaydalar (`timeframe`, `count_distinct`) child + parent Wazuh qaydası kimi çevrilir
- `1 of selection_*` və `1 of filter_*` OR məntiqi dəstəklənir
- Çıxan rule ID-lər sigma `id` sahəsindən stabil hash ilə yaranır (100000+)

## Troubleshooting

**`Group 'group' without any rule`** — Wazuh boş `<group>` qəbul etmir. Minimal `local_rules.xml`:

```bash
sudo tee /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="local,authgraph,">
  <rule id="100001" level="0">
    <description>AuthGraph local rules placeholder</description>
  </rule>
</group>
EOF
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl start wazuh-manager
```
