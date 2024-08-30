# JSParser - Secret-Finder
**JSParser JSParser - Secret-Finder** is a Python-based tool designed to analyze JavaScript files, extract direct API endpoints, and identify sensitive information such as API keys, tokens, and credentials. The tool is built using Flask and provides an easy-to-use web interface to perform these tasks.

## Features
- **Endpoint Extraction:** Detects and extracts direct API URLs from JavaScript files.
- **Sensitive Information Detection:** Identifies and extracts sensitive information, including API keys, OAuth tokens, and private keys.
- **PDF Report Generation:** Generates a PDF report of the extracted information.

## Prerequisites
Ensure you have Python 3.6 or higher installed on your system.

Installation
Clone the Repository

```bash
git clone https://github.com/harshdhamaniya/JSParser-Secret-Finder.git
cd JSParser-Secret-Finder
```

## Create a Virtual Environment (Optional but Recommended)

```bash
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

## Install Required Dependencies
Install all necessary Python packages using the provided requirements.txt file.

```bash
pip install -r requirements.txt
```

## Configuration
You can adjust patterns for sensitive information detection in the sensitive_data_patterns dictionary located in the main script. Customize it as needed to fit your specific use case.

## Running the Application
Start the Flask Application

```bash
python app.py
```

The application will start on **http://0.0.0.0:5443** by default.

Access the Web Interface

Open your web browser and navigate to:

```
http://localhost:5443
```

This will display the JSParser interface.

## Usage

1. **Parse URLs**
   - **Input:** Enter or paste the list of URLs of JavaScript files you want to analyze.
   - **Submit:** Click on the "Parse URLs" button to start the analysis.
   - **Output:** The extracted API endpoints and sensitive information will be displayed on the results page.

2. **Generate PDF Report**
   - **Input:** After parsing URLs, click on the "Generate PDF" button.
   - **Output:** A PDF file containing the analysis results will be generated and downloaded to your local machine.

## Notes

- Make sure the URLs you input are accessible and properly formatted. The tool validates URLs before attempting to fetch and analyze them.
- Sensitive information detection relies on regular expression patterns, which you can customize to detect specific patterns relevant to your analysis.

## License

This project is licensed under the MIT License - see the [`LICENSE`](https://github.com/harshdhamaniya/JSParser-Secret-Finder/blob/main/LICENSE) file for details.

## Contributions

Feel free to submit issues or pull requests to improve the tool.

## Contact

For any inquiries, please reach out via the [GitHub Issues](https://github.com/harshdhamaniya/JSParser-Secret-Finder/issues).
