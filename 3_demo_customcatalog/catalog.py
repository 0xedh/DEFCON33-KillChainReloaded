import shutil
import random
import os
import subprocess
import pefile
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode, quote_plus

#Idea taken from https://github.com/ItzPAX/VulnDriverFinder

class CatalogClient:
    def __init__(self, base_url="https://www.catalog.update.microsoft.com/Search.aspx", timeout=30, max_retries=3):
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()

    def send_search_query(self, query, ignore_duplicates=True, sort_by=None, sort_direction="Descending"):
        """
        Send a search query to the Microsoft Catalog Update website and fetch all pages of results.
        :param query: The search query string
        :param ignore_duplicates: If True, filter out duplicate results
        :param sort_by: Field to sort results by (e.g., "Title", "LastUpdated", etc.)
        :param sort_direction: Sorting direction ("Ascending" or "Descending")
        :return: A list of dictionaries with search results
        """
        all_results = []
        page = 1

        while True:
            encoded_query = quote_plus(query)  # Ensure proper URL encoding
            query_url = f"{self.base_url}?{urlencode({'q': encoded_query, 'p': page})}"
            print(f"Fetching page {page}: {query_url}")

            retries = self.max_retries
            while retries > 0:
                try:
                    response = self.session.get(query_url, timeout=self.timeout)
                    response.raise_for_status()

                    # Parse the page results
                    soup = BeautifulSoup(response.content, "html.parser")
                    results = self._parse_results(soup)
                    if not results:
                        print(f"No more results found on page {page}.")
                        if ignore_duplicates:
                            print("Removing duplicates from results...")
                            all_results = self._remove_duplicates(all_results)
                            print(f"Results after deduplication: {len(all_results)} items")
                        return all_results

                    all_results.extend(results)
                    page += 1  # Move to the next page
                    break

                except requests.exceptions.RequestException as e:
                    retries -= 1
                    print(f"Request failed ({self.max_retries - retries}/{self.max_retries}): {e}")
                    if retries == 0:
                        raise Exception(f"Failed to fetch page {page} after {self.max_retries} retries")

    def _parse_results(self, soup):
        """
        Parse the search results and extract data.
        :param soup: BeautifulSoup object of the search results page
        :return: A list of dictionaries representing the search results
        """
        results = []
        table = soup.find("table", {"id": "ctl00_catalogBody_updateMatches"})
        if not table:
            print("No results table found.")
            return results

        # Extract results from the table
        rows = table.find_all("tr")
        for row in rows[1:]:  # Skip header row
            cols = row.find_all("td")
            if len(cols) < 5:
                continue  # Skip malformed rows

            # Extract the data from the columns
            result = {
                "Title": cols[0].get_text(strip=True),
                "Products": cols[1].get_text(strip=True),
                "OS": cols[2].get_text(strip=True),
                "Classification": cols[3].get_text(strip=True), #drivers, actualizacion, etc
                "LastUpdated": cols[4].get_text(strip=True),
                "Version": cols[5].get_text(strip=True),
                "Size": cols[6].get_text(strip=True),
            }
            #print(result)
            # Find the input element to extract the ID
            input_button = row.find("input", {"class": "flatBlueButtonDownload"})
            if input_button and input_button.has_attr('id'):
                result["InputId"] = input_button["id"]
            else:
                result["InputId"] = None  # If no ID found, set it as None
            if "Drivers" in result["Classification"]: #we're not interested if is not a driver
                results.append(result)

        return results 

    def _remove_duplicates(self, results):
        seen = set()
        deduplicated = []

        for result in results:
            # Create a unique key using all fields
            key = (
                result["Products"].strip(),
                result["Size"].strip()
            )
            if key not in seen:
                deduplicated.append(result)
                seen.add(key)

        return deduplicated

    def _sort_results(self, results, sort_by, sort_direction):
        """
        Sort results based on the given field and direction.
        :param results: List of result dictionaries
        :param sort_by: Field to sort by
        :param sort_direction: "Ascending" or "Descending"
        :return: Sorted list of results
        """
        reverse = sort_direction.lower() == "descending"
        return sorted(results, key=lambda x: x.get(sort_by, ""), reverse=reverse)

    def download_cab_file(self, input_id, output_dir):
        """
        Download the .cab file for the given input ID.
        :param input_id: The unique input ID (updateID) for the download.
        :param output_dir: Directory to save the downloaded .cab file.
        """
        url = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.catalog.update.microsoft.com",
            "Referer": "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
        }

        # Payload as per the example
        payload = {
            "updateIDs": f'[{{"size":0,"languages":"","uidInfo":"{input_id}","updateID":"{input_id}"}}]',
            "updateIDsBlockedForImport": "",
            "wsusApiPresent": "",
            "contentImport": "",
            "sku": "",
            "serverName": "",
            "ssl": "",
            "portNumber": "",
            "version": ""
        }

        try:
            print(f"Initiating download for ID: {input_id}")
            response = self.session.post(url, headers=headers, data=payload, timeout=self.timeout)
            response.raise_for_status()

            # Extract the .cab file URL from the response
            cab_url = self._extract_cab_url(response.text)
            if not cab_url:
                print(f"Failed to extract .cab URL for ID: {input_id}")
                return

            # Download the .cab file
            print(f"Downloading .cab file from: {cab_url}")
            cab_response = self.session.get(cab_url, stream=True, timeout=self.timeout)
            cab_response.raise_for_status()

            # Save the .cab file
            output_file = f"{output_dir}/{input_id}.cab"
            with open(output_file, "wb") as file:
                for chunk in cab_response.iter_content(chunk_size=8192):
                    file.write(chunk)

            print(f"Downloaded .cab file saved to: {output_file}")
        except requests.RequestException as e:
            print(f"Error downloading .cab file for ID {input_id}: {e}")
    def _extract_cab_url(self, html_content):
        """
        Extract the .cab file URL from the HTML content of the POST response.
        :param html_content: The HTML content returned by the POST request.
        :return: The .cab file URL or None if not found.
        """
        # Use a regex to find the JavaScript downloadInformation array
        match = re.search(r"downloadInformation\[0\]\.files\[0\]\.url = '([^']+)'", html_content)
        if match:
            cab_url = match.group(1)
            print(f"Extracted .cab URL: {cab_url}")
            return cab_url
        else:
            print("Failed to extract .cab URL.")
            return None
    def extract_cab(self, cab_file, output_dir):
        """
        Extract the contents of a .cab file.
        :param cab_file: Path to the .cab file.
        :param output_dir: Directory to extract the .cab file contents.
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            print(f"Extracting {cab_file} to {output_dir}...")
            subprocess.run(
                ["cabextract", "-d", output_dir, cab_file],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            print(f"Extraction complete: {output_dir}")
        except subprocess.CalledProcessError as e:
            print(f"Error extracting {cab_file}: {e.stderr.decode().strip()}")

    def analyze_sys_file(self, sys_file, output_dir, functions):
        """
        Analyze a .sys file for specified functions and copy it with a random prefix if a match is found.
        :param sys_file: Path to the .sys file.
        :param output_dir: Directory to copy the .sys file if a match is found.
        :param functions: List of function names to search for.
        """
        try:
            print(f"Analyzing {sys_file} for specified functions...")
            pe = pefile.PE(sys_file)
            found_functions = []

            # Check imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.name.decode() in functions:
                            found_functions.append(imp.name.decode())

            # Check exports
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name and exp.name.decode() in functions:
                        found_functions.append(exp.name.decode())

            if found_functions:
                print(f"Found matching functions in {sys_file}: {found_functions}")
                os.makedirs(output_dir, exist_ok=True)

                # Generate a random 8-digit prefix
                random_prefix = f"{random.randint(10000000, 99999999)}_"
                output_file = os.path.join(output_dir, random_prefix + os.path.basename(sys_file))

                shutil.copy2(sys_file, output_file)  # Copy the file with the prefixed name
                print(f"Copied {sys_file} to {output_file}")
            else:
                print(f"No matching functions found in {sys_file}.")
        except Exception as e:
            print(f"Error analyzing {sys_file}: {e}")


    def clean_up(self, extracted_dir, cab_file=None):
        """
        Delete all files and directories in the extracted directory and optionally the .cab file.
        :param extracted_dir: Directory to clean up.
        :param cab_file: Path to the .cab file to delete.
        """
        try:
            print(f"Cleaning up extracted files in {extracted_dir}...")
            shutil.rmtree(extracted_dir)
            print(f"Cleanup complete: {extracted_dir}")

            if cab_file and os.path.exists(cab_file):
                print(f"Deleting .cab file: {cab_file}")
                os.remove(cab_file)
                print(f".cab file deleted: {cab_file}")

        except Exception as e:
            print(f"Error during cleanup: {e}")

# Example usage


if __name__ == "__main__":
    client = CatalogClient()
    query_file = "queries.txt"
    output_dir = "downloads"
    extracted_dir = "extracted"
    sys_output_dir = "sys_matches"
    """
    functions_to_check = [
        "ZwMapViewOfSection", "MmMapIoSpace",
        "NtOpenProcess", "ZwOpenProcess",
        "NtTerminateProcess", "MmCopyMemory", "PspSetCreateProcessNotifyRoutine",
        "ZwOpenFile",
        "ZwSetValueKey", "ZwTerminateProcess"
    ] #removed IoCreateDevice, check after bulk processing
"""
    functions_to_check = ["ObCloseHandle","ZwTerminateProcess","ZwSuspendthread","ZwOpenProcess","ZwOpenThread","ZwOpenProcessTokenEx","ZwAdjustPrivilegesToken","ZwDeleteFile","ZwCreateFile","IoCreateFile","ZwOpenSymbolicLinkObject","ZwDeleteKey","MmSystemRangeStart","ProbeForRead","ProbeForWrite","MmMapIoSpace","ZwMapViewOfSection","IoAllocateMdl"]
    try:
        if not os.path.exists(query_file):
            raise FileNotFoundError(f"Query file '{query_file}' not found.")

        with open(query_file, "r", encoding="latin1") as file:
            queries = [line.strip() for line in file if line.strip()]

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(extracted_dir, exist_ok=True)
        os.makedirs(sys_output_dir, exist_ok=True)

        for query in queries:
            print(f"Processing query: {query}")
            results = client.send_search_query(query, ignore_duplicates=True, sort_by="LastUpdated")

            print(f"Found {len(results)} results for query '{query}'")
            for result in results:
                input_id = result.get("InputId")
                if input_id:
                    cab_file = os.path.join(output_dir, f"{input_id}.cab")
                    client.download_cab_file(input_id, output_dir)

                    # Extract the .cab file
                    client.extract_cab(cab_file, extracted_dir)

                    # Analyze .sys files in the extracted directory
                    for root, _, files in os.walk(extracted_dir):
                        for file in files:
                            if file.lower().endswith(".sys"):
                                sys_file = os.path.join(root, file)
                                client.analyze_sys_file(sys_file, sys_output_dir, functions_to_check)

                    # Clean up extracted files and delete the .cab file
                    client.clean_up(extracted_dir, cab_file)

    except Exception as e:
        print(f"Error: {e}")
