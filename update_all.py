import requests, json, yaml, logging.config, pytz
from datetime import datetime
from elasticsearch import Elasticsearch

def load_config():
    with open('update_config.yml', 'r') as file:
        return yaml.safe_load(file)

def setup_logging(config):
    logging.config.dictConfig(config)
    return logging.getLogger('update_logger')

def ubah_ke_epoch(tanggal):
    tanggal_obj = datetime.strptime(tanggal, '%Y-%m-%dT%H:%M:%S.%fZ')
    return int(tanggal_obj.timestamp())

def ambil_data_cisa(config):
    url = config['app_config']['cisa_url']
    response = requests.get(url)
    return response.json()

def koneksi_elasticsearch(config):
    es_config = config['app_config']['elasticsearch']
    return Elasticsearch(
        es_config['host'],
        basic_auth=(es_config['username'], es_config['password']),
        verify_certs=False
    )

def simpan_ke_elasticsearch(es, data_vulnerabilities, nama_index, logger):
    zona_waktu = pytz.timezone('Asia/Jakarta')
    
    for vuln in data_vulnerabilities:
        vuln['timestamp'] = datetime.now(zona_waktu).isoformat()
        
        try:
            es.index(
                index=nama_index,
                document=vuln,
                id=vuln['cveID']
            )
            logger.info(f"Berhasil menyimpan CVE: {vuln['cveID']}")
        except Exception as e:
            logger.error(f"Gagal menyimpan: {str(e)}")

def simpan_json_ke_file(data, logger):
    tanggal = datetime.strptime(data["dateReleased"], '%Y-%m-%dT%H:%M:%S.%fZ')
    nama_file = f"kev-{tanggal.strftime('%d-%m-%Y')}.json"
    
    try:
        with open(nama_file, 'w') as file:
            json.dump(data, file, indent=4)
        logger.info(f"Berhasil menyimpan data ke file: {nama_file}")
    except Exception as e:
        logger.error(f"Gagal menyimpan file JSON: {str(e)}")

def main():
    config = load_config()
    logger = setup_logging(config)
    
    data_cisa = ambil_data_cisa(config)
    tanggal_api = ubah_ke_epoch(data_cisa["dateReleased"])
    
    with open('dateReleased.txt', 'r') as file:
        tanggal_file = ubah_ke_epoch(file.read().strip())
    
    if tanggal_api > tanggal_file:
        logger.info("Data baru ditemukan, mulai update Elasticsearch...")
        
        # Simpan JSON ke file
        simpan_json_ke_file(data_cisa, logger)
        
        es = koneksi_elasticsearch(config)
        tanggal_sekarang = datetime.now(pytz.timezone('Asia/Jakarta'))
        nama_index = f"cisa-kev-vulnerabilities-{tanggal_sekarang.strftime('%Y-%m-%d')}"
        
        simpan_ke_elasticsearch(es, data_cisa['vulnerabilities'], nama_index, logger)
        
        with open('dateReleased.txt', 'w') as file:
            file.write(data_cisa["dateReleased"])
        
        logger.info("Update selesai")
    else:
        logger.info("Tidak ada update baru")

if __name__ == "__main__":
    main()
