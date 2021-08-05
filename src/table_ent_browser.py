"""Table browser for entity identification."""
from ipywidgets import HTML
from msticpy.nbtools import nbwidgets

class EntityTableBrowser:
    """Displays a table selection widget showing entities found for each table."""

    def __init__(self, qry_prov, regex_map, table_entities, show_guids=False):
        """
        Initialize class with query provider, regex_map and table_entities

        Parameters
        ----------
        qry_prov : QueryProvider
            Azure Sentinel query provider
        regex_map : Dict[str, Dict[str, str]]
            A dictionary of regex entries.
            For each entry there is a dictionary of properties.
            the regex, the priority and the entity mapping.
            E.g.
            
                "DNS_REGEX": {
                    "regex": r"^((?=[a-z0-9-]{1,63}\.)[a-z0-9]+(-[a-z0-9]+)*\.){1,126}[a-z]{2,63}$",
                    "priority": "1",
                    "entity": "host",
                },
            

        table_entities : Dict[str, Dict[str, Dict[str, Tuple(float, float)]]]
            A dictionary of tables.
            For each table there is a dictionary of columns.
            For each column these is a dictionary of regex matches
            Each match has a tuple of floats
            Item 0 shows the match percentage against non-blank values
            Item 1 shows the match percentage against all rows
        show_guids : bool, optional
            Whether to hide or show GUID regex matches, by default False

        """        
        self.qry_prov = qry_prov
        self.regex_map = regex_map
        self.table_entities = table_entities
        self.show_guids = show_guids
        self.select_item = nbwidgets.SelectItem(
            item_list=list(qry_prov.schema.keys()),
            height="300px",
            action=self._table_match_to_html,
            auto_display=False,
        )
        

    def _table_match_to_html(self, table_name):
        """Return table column matches as HTML table."""
        if table_name not in self.table_entities:
            return HTML("No data")
        
        # Create html table header
        table_html = ["<table><thead><tr><th>Column</th><th>Matches</th></tr></thead><tbody>"]

        for col, matches in self.table_entities[table_name].items():
            col_html = {}
            for rgx_match, perc_match in matches.items():
                if rgx_match == "GUID_REGEX" and not self.show_guids:
                    continue
                # get the entity name and priority for this match
                entity_name = self.regex_map.get(rgx_match, {}).get("entity")
                regex_priority = self.regex_map.get(rgx_match, {}).get("priority", 0)
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
            cols = ",&nbsp;&nbsp;".join(sorted_by_pri)
            # add this as an html table row to the table list
            table_html.append(f"<tr><td><b>{col}</b></td><td>{cols}</td><tr>")
        # add a text heading
        header = "<h2>Column entities</h2>"
        # build and return the table html
        return HTML(f"{header} {''.join(table_html)}</tbody></table>")


    def display(self):
        """Display the browser."""
        display(self.select_item)
