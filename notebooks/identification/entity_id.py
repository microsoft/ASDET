"""Entity Identification Module"""


import numpy as np
import json
import re
import pprint
from pathlib import Path
from typing import Dict, List, Tuple
from IPython.display import HTML
from IPython.display import display
from tqdm.auto import tqdm
from msticpy.nbtools import nbwidgets


DEF_REGEXES = {
    "DNS_REGEX": {
        "regex": r"^((?=[a-z0-9-]{1,63}\.)[a-z0-9]+(-[a-z0-9]+)*\.){1,126}[a-z]{2,63}$",
        "priority": "1",
        "entity": "host",
    },
    "IPV4_REGEX": {
        "regex": r"^(?P<ipaddress>(?:[0-9]{1,3}\.){3}[0-9]{1,3})$",
        "priority": "0",
        "entity": "ipaddress",
    },
    "IPV6_REGEX": {
        "regex": r"^(?<![:.\w])(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}(?![:.\w])$",
        "priority": "0",
        "entity": "ipaddress",
    },
    "URL_REGEX": {
        "regex": r"""
            ^
            (?P<protocol>(https?|ftp|telnet|ldap|file)://)
            (?P<userinfo>([a-z0-9-._~!$&\'()*+,;=:]|%[0-9A-F]{2})*@)?
            (?P<host>([a-z0-9-._~!$&\'()*+,;=]|%[0-9A-F]{2})*)
            (:(?P<port>\d*))?
            (/(?P<path>([^?\#"<>\s]|%[0-9A-F]{2})*/?))?
            (\?(?P<query>([a-z0-9-._~!$&'()*+,;=:/?@]|%[0-9A-F]{2})*))?
            (\#(?P<fragment>([a-z0-9-._~!$&'()*+,;=:/?@]|%[0-9A-F]{2})*))?
            $
            """,
        "priority": "0",
        "entity": "url",
    },
    "MD5_REGEX": {
        "regex": r"^(?:^|[^A-Fa-f0-9])(?P<hash>[A-Fa-f0-9]{32})(?:$|[^A-Fa-f0-9])$",
        "priority": "1",
        "entity": "hash",
    },
    "SHA1_REGEX": {
        "regex": r"^(?:^|[^A-Fa-f0-9])(?P<hash>[A-Fa-f0-9]{40})(?:$|[^A-Fa-f0-9])$",
        "priority": "1",
        "entity": "hash",
    },
    "SHA256_REGEX": {
        "regex": r"^(?:^|[^A-Fa-f0-9])(?P<hash>[A-Fa-f0-9]{64})(?:$|[^A-Fa-f0-9])$",
        "priority": "1",
        "entity": "hash",
    },
    "LXPATH_REGEX": {
        "regex": r"""
            ^(?P<root>/+||[.]+)
            (?P<folder>/(?:[^\\/:*?<>|\r\n]+/)*)
            (?P<file>[^/\0<>|\r\n ]+)$
            """,
        "priority": "2",
        "entity": "file",
    },
    "WINPATH_REGEX": {
        "regex": r"""
            ^(?P<root>[a-z]:|\\\\[a-z0-9_.$-]+||[.]+)
            (?P<folder>\\(?:[^\\/:*?"'<>|\r\n]+\\)*)
            (?P<file>[^\\/*?""<>|\r\n ]+)$
            """,
        "priority": "1",
        "entity": "file",
    },
    "WINPROCESS_REGEX": {
        "regex": r"""
            ^(?P<root>[a-z]:|\\\\[a-z0-9_.$-]+||[.]+)?
            (?P<folder>\\(?:[^\\/:*?"'<>|\r\n]+\\)*)?
            (?P<file>[^\\/*?""<>|\r\n ]+\.exe)$
        """,
        "priority": "0",
        "entity": "process",
    },
    "EMAIL_REGEX": {
        "regex": r"^[\w\d._%+-]+@(?:[\w\d-]+\.)+[\w]{2,}$",
        "priority": "0",
        "entity": "account",
    },
    "RESOURCEID_REGEX": {
        "regex": r"(\/[a-z]+\/)[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}(\/[a-z]+\/).*",
        "priority": "0",
        "entity": "azureresource",
    },
    "NTACCT_REGEX": {
        "regex": r"^([^\/:*?\"<>|]){2,15}\\[^\/:*?\"<>|]{2,15}$",
        "priority": "0",
        "entity": "account",
    },
    "SID_REGEX": {"regex": r"^S-[\d]+(-[\d]+)+$", "priority": "1", "entity": "account"},
    "REGKEY_REGEX": {
        "regex": r"""("|'|\s)?(?P<hive>HKLM|HKCU|HKCR|HKU|HKEY_(LOCAL_MACHINE|USERS|CURRENT_USER|CURRENT_CONFIG|CLASSES_ROOT))(?P<key>(\\[^"'\\/]+){1,}\\?)("|'|\s)?""",
        "priority": "1",
        "entity": "registrykey",
    },
    "GUID_REGEX": {
        "regex": r"^[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}$",
        "priority": "1",
        "data_format": "uuid",
    },
}


QUERY_TEMP = """
{table}
| where {ColumnName} == "{{MySearch}}"
"""


def save_to_json_file(
    data: Dict,
    path: str
):
    """
    Save data to a JSON file at the specified path.

    Parameters
    ----------
    data : Dict
        Contents of the file to be created
    path : str, optional
        File path of the file to be created
    """
    with open(path, "w") as fp:
        json.dump(data, fp)

def read_json_file(path: str):
    """
    Read and return JSON file contents.

    Parameters
    ----------
    path : str, optional
        File path.

    Returns
    -------
    Dict
        JSON file.
    """
    if not Path(path).is_file():
        if "regexes" in path:
            return DEF_REGEXES
        else:
            return
    with open(path) as f:
        return json.load(f)


def add_regex_def(name: str, regex: str, priority: str, entity: str):
    """
    Add additional regexes to the JSON file.

    Parameters
    ----------
    name : str
        Regex name.
    regex : str
        Regex definition.
    priority : str
        Regex priority.
    entity : str
        Entity corresponding to the regex.
    """    
    with open("regexes.json") as json_file:
        data = json.load(json_file)
        y = {name: {"regex": regex, "priority": priority, "entity": entity}}
        data.update(y)
    with open("regexes.json", "w") as f:
        json.dump(data, f)


class EntityIdentifier:
    """Class for identifying entities in the tables of an Azure Sentinel workspace."""    

    def __init__(self, qry_prov):
        """
        Instantiate the EntityIdentifier class.

        Parameters
        ----------
        qry_prov : msticpy.data.data_providers.QueryProvider
            An authenticated query provider that has been connected to an Azure Sentinel workspace.
        """        

        # raw results
        # Dict structure is {table: {column: {regex: (non-blank-matches, all-matches)}}}
        self._regex_matches: Dict[str, Dict[str, Dict[str, Tuple(float, float)]]]
        # object attribute to interpreted results
        self.table_entities: Dict[str, Dict[str, str]]
        # reverse mapping from entities to table/column
        self.entity_map: Dict[str, List[Tuple(str, str)]]
        self.qry_prov = qry_prov
        # load the regexes
        self.regexes = read_json_file("regexes.json")
        # selected tables
        self.selected_tables = nbwidgets.SelectSubset(source_items=list(self.qry_prov.schema.keys()), auto_display=False)

    def save_results(self, path: str = "./results.json"):
        """
        Save _regex_matches, table_entities, and entity_map to a JSON file.

        Parameters
        ----------
        path : str, optional
            File path of the file to be created, by default "./results.json"
        """
        if not self._regex_matches:
            return
        results = {
            "regex_matches": self._regex_matches,
            "table_entities": self.table_entities,
            "entity_map": self.entity_map
        }
        save_to_json_file(results, path)

    def read_results(self, path: str = "./results.json"):
        """
        Read results dict and store the values in designated class variables.

        Parameters
        ----------
        path : str, optional
            File path, by default "./results.json"
        """    
        results = read_json_file(path)
        if results:
            self._regex_matches = results["regex_matches"]
            self.table_entities = results["table_entities"]
            self.entity_map = results["entity_map"]


    def search_single_table(self, table, partial=False, debug=False):
        """
        Apply every regex to every column in the given table.

        Parameters
        ----------
        table : DataFrame
            A table/log queried from the connected Azure Sentinel workspace.
        partial : bool, optional
            If True, searches for substring matches. If False, searches for a match for the entire string, by default False
        debug : bool, optional
            If True, prints the columns for which no match was found, by default False

        Returns
        -------
        Dict[str, Dict[str, Dict[str, Tuple(float, float)]]]
            {table: {column: {regex: (non-blank-matches, all-matches)}}}
        """        
        
        # Dictionary to store results
        full_matches = {}
        # Iterate over each column
        for col in table.columns:
            if len(table[col]) < 1:
                continue
            # Skip non-string columns
            if not isinstance(table[col][0], str):
                if debug:
                    print(f" -- col {col} is type {table[col].dtype}. Skipping")
                continue
            # Iterate over every regex
            for name, regex in self.regexes.items():
                # Strip off ^ and $ delimiters
                if partial:
                    regex = re.sub(r"^\s*\^(.*)\s*\$\s*$", r"\1", regex["regex"])
                # Try the regex on the column
                match_series = table[col].str.match(
                    regex["regex"], case=False, flags=re.VERBOSE
                )
                # If there are more than zero rows in the table
                if len(match_series) > 0:
                    # Calculate the match ratios, including blanks (total_match_ratio)
                    # and not including blanks (match_ratio)
                    total_match_ratio = match_series.sum() / len(match_series)
                    blanks_df = table[col].str.strip() == ""
                    num_non_blanks = len(match_series) - blanks_df.sum()
                    match_ratio = (
                        match_series.sum() / num_non_blanks
                        if num_non_blanks > 0
                        else total_match_ratio
                    )
                    # If at least one entry in the column matched the regex
                    if total_match_ratio > 0:
                        # Add the column, regex, and match ratios to the dict
                        # If this column has already matched with a regex
                        if col in full_matches:
                            full_matches[col][name] = match_ratio, total_match_ratio
                        else:
                            full_matches[col] = {}
                            full_matches[col][name] = match_ratio, total_match_ratio
            if col not in full_matches and debug:
                print(f" -- col {col} no match found")
        return full_matches
        

    def table_match_to_html(self, table_name, show_guids=False):
        """Return table column matches as HTML table."""

        if table_name not in self._regex_matches:
            return HTML("No data")

        # Create html table header
        table_html = [
            "<table><thead><tr><th>Column</th><th>Matches</th></tr></thead><tbody>"
        ]

        for col, matches in self._regex_matches[table_name].items():
            col_html = {}
            for rgx_match, perc_match in matches.items():
                if rgx_match == "GUID_REGEX" and not show_guids:
                    continue
                # Get the entity name and priority for this match
                entity_name = self.regexes.get(rgx_match, {}).get("entity")
                regex_priority = self.regexes.get(rgx_match, {}).get("priority", 0)
                if not entity_name:
                    entity_name = rgx_match
                # Add a row for the column (using a dictionary since we later want to sort
                # based on priority)
                col_html[regex_priority] = (
                    f"<b>{entity_name}</b> [p:{regex_priority}] "
                    f"(matched {rgx_match} {perc_match[0] * 100:0.1f}%,  "
                    f"all rows {perc_match[1] * 100:0.1f}%) "
                )
            # sort the different matches by priority
            sorted_by_pri = [
                value
                for key, value in sorted(col_html.items(), key=lambda item: item[0])
            ]
            # join the matches with some space separators
            cols = "&nbsp;&nbsp;".join(sorted_by_pri)
            # add this as an html table row to the table list
            table_html.append(f"<tr><td><b>{col}</b></td><td>{cols}</td><tr>")
        # add a text heading
        header = "<h2>Column entities</h2>"
        # build and return the table html
        return HTML(f"{header} {''.join(table_html)}</tbody></table>")


    def display_regex_matches(self):
        """
        Displays a widget to allow user to select a table to be matched for regexes.
        """
        nbwidgets.SelectItem(
            item_list=list(self.qry_prov.schema.keys()),
            height="300px",
            action=self.table_match_to_html,
        )

    def interpret_matches(self, regex_matches):
        """
        For each column apply priority and match percentage logic to assign an entity to the column.

        Parameters
        ----------
        regex_matches : Dict
            Output of match_entities function. Dict showing all columns that matched one or more regexes. 
            Dict structure is {table: {column: {regex: (non-blank-matches, all-matches)}}}

        Returns
        -------
        Dict
            Dict structure is {table: {column: entity}}.
        """        
        entity_assignments = {}
        for table, cols in regex_matches.items():
            entity_assignments[table] = {}
            for col, matches in cols.items():
                highest_perc = 0
                highest_pri = 3
                isMatch = False
                for rgx_match, perc_match in matches.items():
                    # Ignore GUID matches
                    if rgx_match == "GUID_REGEX":
                        continue
                    # Choose entity corresponding to the regex with the highest total match percentage
                    # If tie, choose entity with highest priority
                    # 0 has highest priority, 2 is the lowest
                    isMatch = True
                    regex_priority = int(
                        self.regexes.get(rgx_match, {}).get("priority", 0)
                    )
                    if regex_priority < highest_pri:
                        highest_pri = regex_priority
                        rgx = rgx_match
                    if perc_match[0] > highest_perc:
                        highest_perc = perc_match[0]
                        regex = rgx_match
                    elif perc_match[0] == highest_perc:
                        regex = rgx
                if isMatch:
                    entity_name = self.regexes.get(regex, {}).get("entity")
                    entity_assignments[table][col] = entity_name

        return entity_assignments

    def create_entity_map(self, table_entities):
        """
        Iterates through the interpreted results to create a dict keyed by entity type.

        Parameters
        ----------
        table_entities : Dict
            Output of interpret_matches function. Dict of column-entity mappings keyed by table and column.
            Dict structure is {table: {column: entity}}.

        Returns
        -------
        Dict
            Dict structure is Dict: {entity: [(table, col)]}.
        """        
        entity_dict = {}
        for table, cols in table_entities.items():
            for col, entity in cols.items():
                entity_dict[entity] = []
        for table, cols in table_entities.items():
            for col, entity in cols.items():
                entity_dict[entity].append((table, col))
        return entity_dict


    def detect_entities(self, tables=None, sample_size="100"):
        """
        Runs the search_single_table, interpret_matches, and create_entity_map functions on given tables.
        Persists returned values in instance result attributes.

        Parameters
        ----------
        tables : List[str]
            Array of tables in string format to iterate over
        sample_size : str, optional
            Number of events/rows in each table to sample, by default "100"

        Returns
        -------
        Dict
            Output of create_entity_map function. Returns reverse mapping from entities to table and column.
        """        
        if tables is None:
            tables = self.selected_tables.selected_items
        output_regexes = {}
        for table in tqdm(tables):
            df = self.qry_prov.exec_query(f"{table} | sample {sample_size}")
            output_regexes[table] = self.search_single_table(df)
        self._regex_matches = output_regexes
        self.table_entities = self.interpret_matches(self._regex_matches)
        self.entity_map = self.create_entity_map(self.table_entities)
        return self.entity_map


    def detect_entities_random(self, num_tables=3, sample_size=100):
        """
        Runs detect_entities function on any number of random tables.
        """        
        # Generate random list of tables
        tables = []
        for i in range(num_tables):
            table, cols = self.qry_prov.schema.popitem()
            tables.append(table)
        return self.detect_entities(tables)


    def select_tables(self):
        display(self.selected_tables)


    def detect_entities_all_tables(self):
        """
        Run detect_entities function on all tables.
        """
        # List of all tables
        self.detect_entities(self.qry_prov.schema.keys())


    @staticmethod
    def _print_dict(json_dict):
        """
        Prints any dict in a more readable format.
        """
        for table, cols in json_dict.items():
            print(table)

            print("-" * len(table))
            pprint.pprint(cols)


    def disp_regex_matches(self):
        self._print_dict(self._regex_matches)

    def disp_table_entities(self):
        self._print_dict(self.table_entities)

    def disp_entity_map(self):
        self._print_dict(self.entity_map)


    def generate_query(self, entity_type: str, search_value: str, query_template=QUERY_TEMP):
        """
        Generate KQL queries that match the provided template.

        Args:
            entity_type (str): Entity of the particular value to search for in the table schema.
            search_value (str): Value of the instance to search for.
            query_template (str): KQL query template.

        Returns:
            List: List of generated queries.
        """
        queries = []
        for table, matches in self.table_entities.items():
            for col, entity in matches.items():
                if entity_type == entity:
                    # print("found match", table, col, entity)
                    query = query_template.format(table=table, ColumnName=col)
                    queries.append(query.format(MySearch=search_value))
        return queries


def run_queries(self, queries):
    """
    Runs the queries.

    Args:
        queries (List)): Output of generate_query function.
    """
    for query in queries:
        query_result = self.qry_prov.exec_query(query)
        if len(query_result) > 0:
            print(query)
            print("-" * len(query))
            display(query_result)
