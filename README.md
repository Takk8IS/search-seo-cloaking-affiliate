# Search SEO Cloaking Affiliate

![Search SEO Cloaking Affiliate](./assets/screenshot-01.png?raw=true)
![Search SEO Cloaking Affiliate](./assets/screenshot-02.png?raw=true)
![Search SEO Cloaking Affiliate](./assets/screenshot-03.png?raw=true)

This project is a comprehensive tool for analyzing SEO, cloaking, and affiliate marketing data of a given URL. It collects information on backlinks, scripts, meta tags, technologies used, IP details, and more. The tool uses various libraries and APIs to perform in-depth analysis and presents the results in a well-organized format using the `Rich` library.

## Features

-   **Backlinks Analysis**: Collects and displays all backlinks found on the page.
-   **Script Analysis**: Identifies and displays internal and external scripts.
-   **Meta Tags**: Extracts and shows meta tags, including refresh tags.
-   **Obfuscated URLs**: Finds and displays obfuscated URLs in scripts.
-   **Affiliate Information**: Extracts affiliate IDs from the URL.
-   **Domain Information**: Provides WHOIS and DNS details of the domain.
-   **Technologies Used**: Lists technologies used on the site via BuiltWith.
-   **Google Backlinks**: Performs Google search for additional backlinks.
-   **Shodan Integration**: Searches for exposed devices related to the domain.
-   **IP Information**: Detailed IP information using IPWhois.
-   **Port Scanning**: Scans for open ports using nmap.
-   **Traffic Data**: Fetches traffic data using SimilarWeb API.

## Requirements

Ensure all the following Python packages are installed:

```
beautifulsoup4
builtwith
dnspython
google
ipwhois
nmap
python-dotenv
python-whois
requests
rich
shodan
similarweb
socket
tldextract
```

You can install all dependencies using the `requirements.txt` file:

```sh
pip install -r requirements.txt
```

## Usage

1. **Set Up Environment Variables**:

    - Create a `.env` file in the project root.
    - Add the competing affiliate URL.
    - Add your API keys for Shodan and SimilarWeb.

    ```env
    URL=your_competitor_url
    SHODAN_API_KEY=your_shodan_api_key
    SIMILARWEB_API_KEY=your_similarweb_api_key
    ```

2. **Run the Script**:

    - Execute the Python script:

        ```sh
        python search-seo-cloaking-affiliate.py
        ```

3. **View the Results**:
    - The script will output the analysis results in the console, organized using the `Rich` library for better readability.

## Repository

You can find the repository at [github.com/Takk8IS/search-seo-cloaking-affiliate.git](https://github.com/Takk8IS/search-seo-cloaking-affiliate.git)

## Support

If you need help with this project, please contact via email at say@takk.ag.

## Donations

If this script has been helpful for you, consider making a donation to support our work:

-   $USDT (TRC-20): TGpiWetnYK2VQpxNGPR27D9vfM6Mei5vNA

Your donations help us continue developing useful and innovative tools.

## Takk™ Innovate Studio

Leading the Digital Revolution as the Pioneering 100% Artificial Intelligence Team.

-   Copyright (c)
-   Licence: Attribution 4.0 International (CC BY 4.0)
-   Author: David C Cavalcante
-   LinkedIn: https://www.linkedin.com/in/hellodav/
-   Medium: https://medium.com/@davcavalcante/
-   Positive results, rapid innovation
-   URL: https://takk.ag/
-   X: https://twitter.com/takk8is/
-   Medium: https://takk8is.medium.com/
