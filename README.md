# early-warning-cve

Script Python per individuare vulnerabilita recenti e rilevanti associate agli
asset monitorati, generare un report PDF e, quando previsto, inviarlo tramite
email.

## Prerequisiti

- Python 3.9 o versione successiva;
- accesso di rete alle API OpenCVE;
- credenziali applicative per le API OpenCVE;
- un file Excel contenente gli asset da monitorare;
- accesso al servizio Direct Line e alle credenziali dell'agente Copilot, se
  l'arricchimento tramite AI e abilitato;
- accesso a un servizio SMTP, se si desidera inviare il report per email;
- dipendenze Python: `requests`, `urllib3`, `openpyxl`, `python-dotenv` e
  `reportlab`.

Il file Excel deve contenere nella prima riga almeno le colonne:

```text
vendor_name, product_name
```

Il progetto utilizza un file `.env` per separare le impostazioni di esecuzione
dal codice. Il file non deve essere versionato e non deve contenere valori
sensibili nel repository.

## Logica di esecuzione

1. Legge gli asset dal file Excel configurato.
2. Interroga OpenCVE per ogni coppia vendor/prodotto e recupera i dettagli delle
	CVE pubblicate nel periodo di osservazione.
3. Mantiene le vulnerabilita che superano la soglia CVSS oppure EPSS configurata.
4. Ordina i risultati per CVSS decrescente e, a parita, per EPSS decrescente.
5. Se l'integrazione AI e attiva, arricchisce soltanto le prime 20 vulnerabilita
	dell'intero report con analisi di impatto e suggerimenti di remediation.
6. Applica il limite di 999 richieste OpenCVE per ora. Al raggiungimento della
	soglia, sospende il flusso per almeno 60 minuti prima di proseguire.
7. Se un asset genera un errore, lo registra e continua con gli asset successivi.
8. Genera il PDF anche quando non viene trovata alcuna CVE.
9. Invia il PDF tramite email solo quando il report contiene almeno una CVE.

## Esecuzione

Lo script non richiede parametri da riga di comando e puo essere eseguito
manualmente oppure tramite uno scheduler del sistema operativo:

```bash
python script.py
```

## Output

Lo script produce un report PDF datato nella directory e con il nome configurati.
Il report contiene:

- periodo di osservazione;
- riepilogo del numero di vulnerabilita individuate;
- vendor, prodotto e identificativo CVE;
- data di pubblicazione;
- punteggi CVSS ed EPSS;
- descrizione tecnica;
- analisi di business e suggerimenti di remediation per le CVE arricchite con AI.

Quando non sono presenti vulnerabilita, il PDF viene comunque salvato con un
messaggio esplicativo e non viene inviata alcuna email vuota.
