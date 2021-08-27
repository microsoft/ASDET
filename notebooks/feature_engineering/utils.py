import numpy as np
import pandas as pd
import datetime
import re

def cleanEntropy(table, entropyLowerThreshold=0, entropyHigherThreshold=0.5):
    mappedTable = table.applymap(lambda x: str(x) if isinstance(x, list) or isinstance(x, dict) else x)
    for col in mappedTable:
        unique = mappedTable[col].nunique()
        if unique == 0:
            table = table.drop(col, axis=1)
            continue
        maxEntropy = np.log2(mappedTable[col].nunique())
        prob = mappedTable[col].value_counts(normalize=True, sort=False)
        entropy = -1 * (((prob * np.log2(prob))).sum())
        if maxEntropy == 0 or ( entropyLowerThreshold > entropy / maxEntropy > entropyHigherThreshold):
            table = table.drop(col, axis=1)
    return table

def cleanDuplicates(table, keepEmptyCol=False):
    emptyCol = []
    # Casting variables to allowing hashing
    cleanTable = table.applymap(lambda x: str(x) if isinstance(x, list) or isinstance(x, dict) or isinstance(x, datetime.datetime) else x)
    # Finds empty columns to prevent them from being dropped
    if keepEmptyCol:
        for column in cleanTable:
            # Convert to numpy
            data = cleanTable[column].to_numpy() 
            if (data[0] == np.nan or data[0] == '') and (data[0] == data).all():
                emptyCol.append(column)
        # Copy columns over to be added back after duplicates are removed
        col = cleanTable[emptyCol]
        cleanTable = cleanTable.drop(col, axis=1)

    # Transpose the cleaned table and drop duplicate columns. Re-transpose to get rows back into original columns
    cleanTable = cleanTable.T.drop_duplicates().T

    # Return non-duplicate columns for uncasted table
    return table[list(cleanTable)+emptyCol]

def cleanRegexes(table, regexes=[]):
    for feature in table:
        for regex in regexes:
            if re.match(regex, feature):
                table = table.drop([feature], axis=1)
                break
    return table

def binarizeTable(table: pd.DataFrame, removeNaN: bool = True):
    """[Function for binarizing a table given the presence or absence of data. i.e. if the first two columns of a dataframe row are empty followed by two present the binarized form would be 0011]
    Args:
        table (pd.DataFrame): [Pandas dataframe to binarize]
        removeNaN (bool, optional): [Boolean that describes whether NaN values should be removed]. Defaults to True.
    Returns:
        [pd.Dataframe]: [Returns binarized table]
    """

    # Replace empty cells with NaN 
    if removeNaN:
        binTable = table.replace(r'^\s*$', np.nan, regex=True)

    # Replace NaN values with 0 and all others with 1
    binTable = binTable.notnull().astype('int')

    return binTable

def cleanInvariant(table):
    # Casting variables to allowing hashing
    cleanTable = table.applymap(lambda x: str(x) if isinstance(x, list) or isinstance(x, dict) or isinstance(x, datetime.datetime) else x)
    
    for feature in cleanTable:
        if cleanTable[feature].nunique() <= 1:
            table = table.drop([feature], axis=1)
    return table

def cleanTable(table, removeDuplicates=True, keepEmptyCol=False, removeInvariant=True, cleanEntropy=False, entropyLowerThreshold=0, entropyHigherThreshold=0.5, regexes=[]):
    if removeDuplicates:
        table = cleanDuplicates(table, keepEmptyCol=keepEmptyCol)
    if removeInvariant:
        table = cleanInvariant(table)
    if regexes:
        table = cleanRegexes(table, regexes=regexes)
    if cleanEntropy:
        table = cleanEntropy(table, entropyLowerThreshold=entropyLowerThreshold, entropyHigherThreshold=entropyHigherThreshold)
    return table