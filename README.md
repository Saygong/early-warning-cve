# early-warning-cve

Script automatico per individuare vulnerabilita recenti e critiche associate agli
asset aziendali e produrre un'analisi in linguaggio business tramite un agente
Copilot Studio.

## Funzionalità

- legge vendor e prodotto dal file Excel degli asset;
- interroga OpenCVE e recupera i dettagli completi delle CVE;
- mantiene le vulnerabilita pubblicate negli ultimi `LOOKBACK_DAYS` giorni;
- mantiene le CVE con `CVSS >= CVSS_THRESHOLD` oppure `EPSS >= EPSS_THRESHOLD`;
- invia il JSON completo di ogni vulnerabilita a Copilot Studio tramite Direct Line API;
- attende la risposta dell'agente con polling;
- salva dati CVE e analisi business nel CSV di output.

## Prerequisiti

Installare le dipendenze Python:

```text
requests
urllib3
openpyxl
python-dotenv
```

Il file Excel deve contenere almeno queste colonne nella prima riga:

```text
vendor_name, product_name
```

## Configurazione

Creare un file `.env` nella cartella del progetto. `OPENCVE_API_TOKEN`,
`COPILOT_AGENT_SECRET`, `CVSS_THRESHOLD`, `EPSS_THRESHOLD` e
`DIRECT_LINE_BASE_URL` sono obbligatorie. Le altre variabili hanno un valore
predefinito:


`OPENCVE_VERIFY=false` disabilita la verifica dei certificati SSL e silenzia gli
avvisi relativi ai certificati self-signed. La stessa impostazione viene applicata
anche alle richieste Direct Line. Viene fatto ciò in quanto la verifica del certificato SSL fallisce a causa della SSL inspection del proxy aziendale.

Non inserire token o secret nel repository. Il file `.env` deve rimanere escluso
dal versionamento.

## Esecuzione

Lo script non richiede parametri e puo essere eseguito direttamente o pianificato
con l'utilita di schedulazione del sistema operativo:

```bash
python script.py
```

In caso di errore su un singolo asset, lo script registra il problema e prosegue
con gli asset successivi.

## Output

Il CSV contiene le informazioni della vulnerabilita e la colonna aggiuntiva:

```text
Business Impact Analysis
```

L'analisi generata descrive in massimo 100 parole i potenziali impatti, l'eventuale
presenza di un exploit pubblico e le conseguenze della mancata applicazione della
patch.
