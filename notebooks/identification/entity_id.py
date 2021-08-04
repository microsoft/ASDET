import numpy as np
import json
import re
import pprint
import ipywidgets as widgets

""" Entity Identification Module """

regexes = {
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
        "priority": "1",
        "entity": "process",
    },
    'EMAIL_REGEX': {
        'regex': r"^[\w\d._%+-]+@(?:[\w\d-]+\.)+[\w]{2,}$", 
        'priority': '0', 
        'entity': 'account'
    },
    'RESOURCEID_REGEX': {
        'regex': r"(\/[a-z]+\/)[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}(\/[a-z]+\/).*", 
        'priority': '0', 
        'entity': 'azureresource'
    },
    'NTACCT_REGEX': {
        'regex': r"^([^\/:*?\"<>|]){2,15}\\[^\/:*?\"<>|]{2,15}$", 
        'priority': '0', 
        'entity': 'account'
    },
    'SID_REGEX': {
        'regex': r"^S-[\d]+(-[\d]+)+$", 
        'priority': '1', 
        'entity': 'account'
    },
    'REGKEY_REGEX': {
        'regex': r"""("|'|\s)?(?P<hive>HKLM|HKCU|HKCR|HKU|HKEY_(LOCAL_MACHINE|USERS|CURRENT_USER|CURRENT_CONFIG|CLASSES_ROOT))(?P<key>(\\[^"'\\/]+){1,}\\?)("|'|\s)?""", 
        'priority': '1', 
        'entity': 'registrykey'
    },
    'GUID_REGEX': {
        'regex': r"^[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}$", 
        'priority': '1', 
        'data_format': 'uuid'
    }
}

def save_regex_defs(data=regexes, path="./", file_name="regexes"):
    """
    Save all entity regexes to a JSON file.

    Args:
        data (dict, optional): Contents of the file to be created. Defaults to regexes.
        path (str, optional): File path of the file to be created. Defaults to "./".
        file_name (str, optional): Name of the file to be created. Defaults to "regexes".
    """
    filePathNameWExt = "./" + path + "/" + file_name + ".json"
    with open(filePathNameWExt, "w") as fp:
        json.dump(data, fp)


def add_regex_def(name, regex, priority, entity):
    """
    Add additional regexes to the JSON file.

    Args:
        name (str): Regex name.
        regex (str): Regex definition.
        priority (str): Regex priority.
        entity (str): Entity corresponding to the regex.
    """
    with open ('regexes.json') as json_file:
        data = json.load(json_file)
        y = {name: {'regex': regex, 'priority': priority, 'entity': entity}}
        data.update(y)
    with open ('regexes.json', 'w') as f:
        json.dump(data, f)


def read_regex_defs():
    """
    Read and return regex dict.

    Returns:
        dict: Regex dict stored in regexes.json.
    """
    with open('regexes.json') as f:
        return json.load(f)


class EntityIdentifier:

    def __init__(self, qry_prov):
        # raw results
        self._regex_matches: dict[table, dict[column, matches]]
        # object attribute to interpreted results
        self.table_entities: dict[table_name, dict[col_name, entity]]
        # reverse mapping from entities to table/column
        # self.entity_map: dict[entity, tables_cols_arr]
        self.qry_prov = qry_prov


    def search_single_table(self, table, partial=False, debug=False):
        """
        Apply every regex to every column in the given table.

        Args:
            table (DataFrame): A table/log queried from the connected Azure Sentinel workspace.
            partial (bool, optional): If True, searches for substring matches. If False, searches for a match for the entire string. Defaults to False.
            debug (bool, optional): If True, prints the columns for which no match was found. Defaults to False.

        Returns:
            dict: {Column: {Regex: (Match ratio excluding blanks, Match ratio including blanks)}}
        """
        # Dictionary to store results
        full_matches = {}
        # Iterate over each column   
        for col in table.columns:
            # Skip non-string columns
            if table[col].dtype != np.dtype("O"):
                if debug:
                    print(f" -- col {col} is type {table[col].dtype}. Skipping")
                continue
            # Iterate over every regex
            for name, regex in regexes.items():
                # Strip off ^ and $ delimiters
                if partial:
                    regex = re.sub(r"^\s*\^(.*)\s*\$\s*$", r"\1", regex["regex"])
                # Try the regex on the column
                match_series = table[col].str.match(regex['regex'], case=False, flags=re.VERBOSE)
                # If there are more than zero rows in the table
                if len(match_series) > 0:
                    # Calculate the match ratios, including blanks (total_match_ratio) 
                    # and not including blanks (match_ratio)
                    total_match_ratio = match_series.sum() / len(match_series)
                    blanks_df = table[col].str.strip() == ""
                    num_non_blanks = len(match_series) - blanks_df.sum()
                    match_ratio = match_series.sum() / num_non_blanks if num_non_blanks > 0 else total_match_ratio
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

        self._regex_matches = self.search_single_table(table_name)

        if table_name not in self._regex_matches:
            return HTML("No data")
        
        # Create html table header
        table_html = ["<table><thead><tr><th>Column</th><th>Matches</th></tr></thead><tbody>"]

        for col, matches in self._regex_matches[table_name].items():
            col_html = {}
            for rgx_match, perc_match in matches.items():
                if rgx_match == "GUID_REGEX" and not show_guids:
                    continue
                # Get the entity name and priority for this match
                entity_name = regexes.get(rgx_match, {}).get("entity")
                regex_priority = regexes.get(rgx_match, {}).get("priority", 0)
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
            sorted_by_pri = [value for key, value in sorted(col_html.items(), key=lambda item: item[0])]
            # join the matches with some space separators
            cols = "&nbsp;&nbsp;".join(sorted_by_pri)
            # add this as an html table row to the table list
            table_html.append(f"<tr><td><b>{col}</b></td><td>{cols}</td><tr>")
        # add a text heading
        header = "<h2>Column entities</h2>"
        # build and return the table html
        return HTML(f"{header} {''.join(table_html)}</tbody></table>")


    def get_regex_matches(self):
        """
        Displays a widget to allow user to select a table to be matched for regexes.
        """
        nbwidgets.SelectItem(item_list=list(self.qry_prov.schema.keys()), height="300px", action=self.table_match_to_html)
        

    def interpret_matches(self, regex_matches):
        """
        For each column apply priority and match percentage logic to assign an entity to the column.
            
        Args:
            table_match_dic (Dict): Output of match_entities function. Dict showing all columns that matched one or more regexes.
        Returns:
            Dictionary: {Table: {Column: Entity}}
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
                    regex_priority = int(regexes.get(rgx_match, {}).get("priority", 0))
                    if regex_priority < highest_pri:
                        highest_pri = regex_priority
                        rgx = rgx_match
                    if perc_match[0] > highest_perc:
                        highest_perc = perc_match[0]
                        regex = rgx_match
                    elif perc_match[0] == highest_perc:
                        regex = rgx
                if(isMatch):
                    entity_name = regexes.get(regex, {}).get("entity")
                    entity_assignments[table][col] = entity_name

        return entity_assignments

    def create_entity_map(self, table_entities):
        """
        Iterates through the interpreted results to create a dict keyed by entity type.

        Args:
            table (Dict): Output of interpret_matches function. Dict of column-entity mappings keyed by table and column.

        Returns:
            Dict: {entity: [(table, col)]}
        """
        entity_dict = {}
        for table, cols in table_entities.items():
            for col, entity in cols.items():
                entity_dict[entity] = []
        for table, cols in table.items():
            for col, entity in cols.items():
                entity_dict[entity].append((table, col))
        return entity_dict

    def detect_entities_random(self, num_tables=3, sample_size='100'):
        """
        Runs the match_regexes, interpret_matches, and create_entity_index functions on three random non-empty tables in the schema by default. 

        Args:
            num_tables (int, optional): Number of random tables to sample. Defaults to 3.
            sample_size (str, optional): Number of events/rows in each table to sample. Defaults to '100'.

        Returns:
            Dict: Output of create_entity_map function. Returns reverse mapping from entities to table and column.
        """
        output_regexes = {}

        for i in range(num_tables):
            table, cols = self.qry_prov.schema.popitem()
            df = self.qry_prov.exec_query(f"{table} | sample 100")
            while len(df) == 0:
                table, cols = self.qry_prov.schema.popitem()
                df = self.qry_prov.exec_query(f"{table} | sample 100")
            output_regexes[table] = self.search_single_table(df)
        output_entities = self.interpret_matches(output_regexes)
        keyed_entities = self.create_entity_map(output_entities)
        return keyed_entities


    def detect_entities_in_passed_tables(self, tables, sample_size='100'):
        """
        Runs the match_regexes, interpret_matches, and create_entity_map functions on selected tables in the schema. 

        Args:
            tables ([str]): Array of tables in string format that we want iterate over
            sample_size (str, optional): Number of events/rows in each table to sample. Defaults to '100'.

        Returns:
            Dict: Output of create_entity_map function. Returns reverse mapping from entities to table and column.
        """
        output_regexes = {}

        for i in range(len(tables)):
            table = tables[i]
            df = self.qry_prov.exec_query(f"{table} | sample {sample_size}")
            output_regexes[table] = self.match_regexes(df)
        output_entities = self.interpret_matches(output_regexes)
        keyed_entities = self.create_entity_map(output_entities)
        return keyed_entities


    def detect_entities(self):
        """
        Displays a widget to allow user to select tables to detect entities in.

        Returns:
            Dict: Reverse mapping from entities to table and column.
        """
        sel_sub = nbwidgets.SelectSubset(source_items=list(self.qry_prov.schema.keys()))
        return self.detect_entities_in_passed_tables(sel_sub.selected_items)


    def print_dict(self, json_dict):
        """
        Prints dict in a more readable format.

        Args:
            json_dict (dict): Any nested dictionary.
        """
        for table, cols in json_dict.items():
            print(table)
        
            print("-" * len(table))
            pprint.pprint(cols)


    def generate_query(self, entity_type, search_value, query_template):
        """
        Generate KQL queries that match the provided template.

        Args:
            entity_type (str): Entity of the particular value to search for in the table schema.
            search_value (str): Value of the instance to search for.
            query_template (str): KQL query template.

        Returns:
            List: List of generated queries.
        """
        email_queries = []
        for table, matches in self.table_entities.items():
            for col, entity in matches.items():
                if entity_type == entity:
                    # print("found match", table, col, entity)
                    query = query_template.format(table=table, ColumnName=col)
                    email_queries.append(query.format(MySearch=search_value))
        return email_queries


def display_queries(self, queries):
    """
    Runs the queries.

    Args:
        queries (List)): Output of generate_query function.
    """
    for query in queries:
        query_result=qry_prov.exec_query(query)
        if len(query_result) > 0:
            print(query)
            print("-" * len(query))
            display(query_result)

    


