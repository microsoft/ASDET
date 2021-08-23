"""Widget to browse table/column structure."""

import ipywidgets as widgets
from IPython.display import HTML, display


class AzSentColumnSelector:
    """
    Table/column browser with actions to display related col properties.

    Examples
    --------
    This will load and display the widget with the default column details.
    >>> wgt = AzSentColumnSelector(qry_prov)
    >>> wgt

    This sample defines an alternative column action
    >>> def column_display(table, col):
    >>>     col_dict = qry_prov.schema[table]
    >>>     return HTML(f"<h3>{col}</h3>The datatype for this column is: {col_dict[col]}")
    >>>
    >>> AzSentColumnSelector(qry_prov, column_display)

    """
    
    # define layout
    LIST_LAYOUT = widgets.Layout(height="300px", width="30%")

    def __init__(self, qry_prov, column_action=None):
        """
        Initialize an instance of the Azure Sentinel table browser.

        Parameters
        ----------
        qry_prov : QueryProvider
            Azure Sentinel query provider.
        column_action : Callable[[None], str, str], optional
            Function taking parameters `table`, `column` that returns
            an IPython-displayable object, by default None

        """        
        self.schema_dict = qry_prov.schema
        self._column_action = column_action or self._default_col_action

        # create widgets
        self.table_select = widgets.Select(
            description="table",
            options=list(self.schema_dict.keys()),
            layout=self.LIST_LAYOUT
        )
        # add event handler to widget   
        self.table_select.observe(self._get_columns, names="value")

        self.col_select = widgets.Select(
            description="column",
            options=[],
            layout=self.LIST_LAYOUT
        )
        # add handler
        self.col_select.observe(self._get_col_details, names="value")

        # html widget to display text stuff
        self._disp_handle = None
        
        # display widgets using VBox and HBox layout controls
        self.layout = widgets.HBox([self.table_select, self.col_select])
        
    @property
    def selected_table(self) -> str:
        """Return the selected table."""
        return self.table_select.value

    @property
    def selected_column(self) -> str:
        """Return the selected column."""

    def display(self):
        """Display the control."""
        display(self.layout)
        self._disp_handle = display("details", display_id=True)
        # prob a nicer way to do this but we want to force the
        # event handlers to be called on the first item so that
        # everything is populated when first shown
        self._get_columns({"new": list(self.schema_dict.keys())[0]})
        
    def _ipython_display_(self):
        """Display in IPython."""
        self.display()

    def _get_columns(self, change):
        """Event handler for table_select."""
        table = change.get("new")
        if table and table in self.schema_dict:
            self.col_select.options = sorted(list(self.schema_dict[table].keys()))
        else:
            self.col_select.options = []
    
    def _get_col_details(self, change):
        """Event handler for col_select."""
        col = change.get("new")
        if self._disp_handle:
            self._disp_handle.update(self._column_action(self.table_select.value, col))
        
    def _default_col_action(self, table, col):
        """Default action if nothing is supplied"""
        col_dict = self.schema_dict.get(table)
        if col and col_dict and col in col_dict:
            return HTML(f"<h3>{col}</h3>datatype: {col_dict[col]}")
