"""Utility functions for Azure Sentinel tables."""
from typing import Dict, List, Optional
import pandas as pd
from tqdm.auto import tqdm


def get_table_variability(qry_prov, table_subset: Optional[List[str]] = None) -> Dict[str, str]:
    """
    Return column variability for each table in the schema.

    Parameters
    ----------
    qry_prov: QueryProvider
        Azure Sentinel query provider.

    Returns
    -------
    Dict[str, str]
        Dictionary of table_name, variability. Variability can be
        no_data, variable, constant.
        "variable" indicates that the ratio of the number of columns
        that are sometimes filled / number of columns always filled is > 1.
        "constant" indicates the above ratio is < 1.
        "no_data" indicates that the table is empty.

    Examples
    --------
    Get the column variability for tables listed in the provider
    >>> table_results = get_table_variability(qry_prov)

    """
    if not table_subset:
        print("warning: long-running function...")
    table_results = {}

    for table in tqdm(qry_prov.schema, unit="table"):
        if table_subset and table not in table_subset:
            continue
        data = qry_prov.exec_query(f"{table} | sample 100")
        if data.empty:
            table_results[table] = "no_data"
            continue
        col_var = _col_variability(data)
        table_results[table] = "variable" if col_var > 1 else "constant"
    return table_results
        


def _get_groupings(input_df):
    """Return groupings of table data based on filled/empty columns."""
    input_cols = list(input_df.columns)
    # change any NAs to blank strings (this might cause TypeErrors !)
    input_df = input_df.fillna("")
    # Create a DF with True if a col value is blank
    blank_cols = input_df == ""

    # save the index as "orig_index" column
    blank_cols = blank_cols.reset_index().rename(columns={"index": "orig_index"})

    # remove one col - since we need something to count() in our group_by
    # statement
    # TenantId is a good choice since we know it's always non-blank
    # and the same value
    input_cols.remove("TenantId")
    # group the bool DF by all the cols
    return (
        blank_cols
        .groupby(list(input_cols))
        .count()
        .reset_index()  # reset index to get back a DF
        .reset_index()  # reset again to create an "index" column
        .rename(columns={"TenantId": "count", "index": "group_index"})
        .drop(columns=["orig_index"])
    )


def _col_variability(input_df: pd.DataFrame) -> float:
    """
    Return the variability that columns are filled/empty.
    
    Parameters
    ----------
    input_df : pd.DataFrame
        The input DataFrame

    Returns
    -------
    float
        Variability score
        Variability is calculated as the ratio of columns that are sometimes
        filled and sometimes empty to the number of always-filled
        columns in the table.

    """
    res_df = _get_groupings(input_df)
    mean_diffs = pd.DataFrame(res_df.drop(columns=["group_index", "count"]).mean(), columns=["mean_diff"])
    var_cols = mean_diffs[(mean_diffs["mean_diff"] > 0) & (mean_diffs["mean_diff"] < 1)]
    return (len(var_cols) / len(mean_diffs[mean_diffs["mean_diff"] == 0]))