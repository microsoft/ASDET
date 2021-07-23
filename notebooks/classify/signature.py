import numpy as np
import pandas as pd
import re
import datetime

# Function for cleaning extraneous features from a pandas dataframe
# Parameters
#   table: pandas dataframe
#   exactMatches: List of features (str) to remove if an exact match occurs
#   regexes: List of regexes (str) to remove if the regular expression matches any features
#   removeDuplicates: boolean that determines if duplicates should be removed
#   isInvariant: boolean that determines if invariant columns should be removed
# Returns:
#   Pandas dataframe that has been cleaned

def cleanData(table, exactMatches=[], regexes=[], removeDuplicates=True, isInvariant=True):
    print('Cleaning Table.')
    cleanTable = table.applymap(lambda x: str(x) if isinstance(x, list) or isinstance(x, dict) or isinstance(x, datetime.datetime) else x)
    
    # Remove features that may be continuous values (i.e. time) using regular expressions and exact matches
    
    for feature in cleanTable:
        
        # Check if this feature is included in our exactMatches to remove
        
        if feature in exactMatches:
            cleanTable = cleanTable.drop([feature], axis=1)
            print('{feature} due to being an exact match'.format(feature=feature))
            continue
        
        # Check if the values in a column are all the same, if so we remove
        
        if isInvariant and cleanTable[feature].nunique() <= 1:
            print('{feature} due to being an invariant column.'.format(feature=feature))
            cleanTable = cleanTable.drop([feature], axis=1)
            continue
            
        # Else compare to regular expressions
            
        for regex in regexes:
            if re.match(regex, feature):
                cleanTable = cleanTable.drop([feature], axis=1)
                print('{feature} due to being a match with regular expression: {regex}'.format(feature=feature, regex=regex))
                break

    if removeDuplicates:
        # Finds empty columns to prevent them from being dropped
        emptyCol = []
        for column in cleanTable:
            # Convert to numpy
            data = cleanTable[column].to_numpy() 
            if (data[0] == np.nan or data[0] == '') and (data[0] == data).all():
                emptyCol.append(column)
                
        # Copy columns over to be added back after duplicates are removed
        col = cleanTable[emptyCol]
        
        # Transpose the cleaned table and drop duplicate rows. Re-transpose to get back to the original table
        cleanTable = cleanTable.T.drop_duplicates().T
        
        # Add empty columns back into table and reorder
        cleanTable = pd.concat([cleanTable, col], axis=1)
    return cleanTable

# Function for binarizing a table given the presence or absence of data
#   i.e. if the first two columns of a dataframe row are empty followed by two present the binarized form would be 0011
# Parameters:
#   table: pandas dataframe
#   removeNan: boolean that describes whether NaN values should be removed
# Returns:
#   pandas dataframe that has been binarized

def binarizeData(table, removeNaN=True):

    # Replace empty cells with NaN 
    if removeNaN:
        binTable = table.replace(r'^\s*$', np.nan, regex=True)

    # Replace NaN values with 0 and all others with 1
    binTable = binTable.notnull().astype('int')

    return binTable

# Function that returns a list of missing and present features given the binary data signature
# Parameters:
#   signature: string of 0's and 1's representing the data signature
#   columns: list of columns (str) in the signature
# Returns:
#   1. List of present columns (str)
#   2. List of missing columns (str)

def getPresentColumns(signature, columns):
    present = []
    missing = []
    for index in range(len(signature)):
        if int(signature[index]):
            present.append(columns[index])
        else:
            missing.append(columns[index])
    return present, missing

# Function that counts the number of times a datapoint shows up in the features
#   For example, it counts how many times the IP 44.150.161.58 shows up in the clientIP column
# Parameters:
#   row: Row from pandas dataframe (pandas series)
#   columns: List of columns (str) in table
#   presentFeatures: List of present features (str) in table
#   featureDict: A dictionary that maps the number of occurrences of a feature in a column
#       key: feature (str)
#       value: # of occurrences (int)

def countTypes(row, columns, presentFeatures, featureDict):
    for index in range(len(row)):
        
        currentFeature = columns[index]
        value = row[index]
        
        # If the feature is missing we won't count it
        if currentFeature not in presentFeatures:
            continue
            
        if value not in featureDict[currentFeature]:
            featureDict[currentFeature][value] = 1
        else:
            featureDict[currentFeature][value] += 1
    return featureDict

# Function for generating data signatures from table given the presence/absence of data
#   Parameters:
#       binTable: binarized dataframe generated from raw dataframe
#       cleanTable: cleaned dataframe geneated from raw dataframe
#   Returns:
#       signaturedict: dictionary
#           key: signature
#           value(s):
#               count: # of features (int)
#               presentFeatures: list of features (str)
#               missingFeatures: list of features (str)
#               featureDict:
#                   key: feature (str)
#                   values:
#                       dictionary of {(feature): {value}}  and their counts

def generate(binTable, cleanTable):

    print('Generating dictionary of signatures for table.')
    columns = binTable.columns
    signatureDict = {}
    
    for index, row in binTable.iterrows():
        signature = ''.join(map(str, row.values.tolist()))
        
        # If this signature does not exist
        if signature not in signatureDict:
            
            # Identify Present/Missing features
            present, missing = getPresentColumns(signature, columns)
            # Generate and update number of different data types in the feature dictionary
            featureDict = {i: {} for i in present}
            featureDict = countTypes(cleanTable.iloc[index], columns, present, featureDict)
            
            signatureDict[signature] = {
                'count': 1,
                'presentFeatures': present,
                'missingFeatures': missing,
                'featureDict': featureDict
            }
        else:
            signatureDict[signature]['count'] += 1
            signatureDict[signature]['featureDict'] = countTypes(cleanTable.iloc[index], columns, signatureDict[signature]['presentFeatures'], signatureDict[signature]['featureDict'])

    return signatureDict

# A function that finds the unique values within a given signature
# Parameters:
#   table: pandas dataframe that is a dictionary of signatures
#   threshold: threshold value (int) that defines a unique value
#   uniqueTable: boolean that determine whether we want to print out values unique to the table
# Returns:
#   signatureDict: dictionary that contains unique values for each signature
#   counts: dictionary that displays counts of values within each signature

def findUniques(table, threshold=1, uniqueTable=True):

    if threshold < 1:
        print("You set a threshold less than 1, automatically set to 1.")
        threshold = 1

    signatureDict = {}

    counts = {}
    for signature, properties in table.items():
        featureDict = properties['featureDict']
        uniqueFeatures = []
        for feature, values in featureDict.items():
            if len(values.keys()) <= threshold:
                uniqueFeatures.append({feature: list(values.keys())[0]})
                key = (feature, list(values.keys())[0])
                if key in counts:
                    counts[key] += 1
                else:
                    counts[key] = 1
        signatureDict[signature] = uniqueFeatures

    return signatureDict, counts

# Function that displays the unique value for a given signature
# Parameters:
#   signatureDict: a dictionary that contains unique values for each signature
#   counts: dictionary that displays counts of values within each signature
#   signature: signature string to analyze

def displayUniques(signatureDict, counts, signature):
    print(f"Unique value for the signature {signature} are as follows")
    for feature in signatureDict[signature]:
        key = (list(feature.keys())[0], feature[list(feature.keys())[0]])
        if counts[key] == 1:
            print(key, 'is unique through the entire table')
        else:
            print(key)