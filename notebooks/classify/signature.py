import numpy as np
import pandas as pd
import re
import datetime
import matplotlib.pyplot as plt
import ipywidgets as widgets
from typing import Dict, List

class DataSignature:
    def __init__(self, table: pd.DataFrame, DEBUG: bool = False):
        """[Class for generating data signatures for a table and finding unique values within a signature.]

        Args:
            table (pd.DataFrame): [Pandas dataframe to geneate signatures for]
            DEBUG (bool, optional): [Debug flag]. Defaults to False.
        """
        self.table = table
        self.DEBUG = DEBUG
        self.binData = None
        self.cleanedData = None
        self.signatureDict = None
        self.featureMap = None
        self.uniqueFeatures = None
        self.featureValueCounts = None

    def cleanData(self, exactMatches=[], regexes=[], removeDuplicates=True, isInvariant=True):
        """[Function for cleaning extraneous features from a pandas dataframe]

        Args:
            exactMatches (list, optional): [List of features to remove if an exact match occurs]. Defaults to [].
            regexes (list, optional): [List of regexes to remove if the regular expression matches any features]. Defaults to [].
            removeDuplicates (bool, optional): [Boolean that determines if duplicates should be removed]. Defaults to True.
            isInvariant (bool, optional): [Boolean that determines if invariant columns should be removed]. Defaults to True.

        Returns:
            [pd.Dataframe]: [Pandas dataframe that has been cleaned]
        """
        cleanTable = self.table.applymap(lambda x: str(x) if isinstance(x, list) or isinstance(x, dict) or isinstance(x, datetime.datetime) else x)
        
        # Remove features that may be continuous values (i.e. time) using regular expressions and exact matches
        
        for feature in cleanTable:
            
            # Check if this feature is included in our exactMatches to remove
            
            if feature in exactMatches:
                cleanTable = cleanTable.drop([feature], axis=1)
                # print('{feature} due to being an exact match'.format(feature=feature))
                continue
            
            # Check if the values in a column are all the same, if so we remove
            
            if isInvariant and cleanTable[feature].nunique() <= 1:
                # print('{feature} due to being an invariant column.'.format(feature=feature))
                cleanTable = cleanTable.drop([feature], axis=1)
                continue
                
            # Else compare to regular expressions
                
            for regex in regexes:
                if re.match(regex, feature):
                    cleanTable = cleanTable.drop([feature], axis=1)
                    # print('{feature} due to being a match with regular expression: {regex}'.format(feature=feature, regex=regex))
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

    def binarizeData(self, table: pd.DataFrame, removeNaN: bool = True):
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

    def getPresentColumns(self, signature: str, columns: List[str]):
        """[Function that returns a list of missing and present features given the binary data signature]

        Args:
            signature (str): [string of 0's and 1's representing the data signature]
            columns (List[str]): [list of columns in the signature]

        Returns:
            [List[str]]: [List of present columns and missing columns]
        """
        present = []
        missing = []
        for index in range(len(signature)):
            if int(signature[index]):
                present.append(columns[index])
            else:
                missing.append(columns[index])
        return present, missing

    def countTypes(self, row: pd.Series, columns: List[str], presentFeatures: List[str], featureDict: Dict):
        """[Function that counts the number of times a datapoint shows up in the features. For example, it counts how many times the IP 44.150.161.58 shows up in the clientIP column]

        Args:
            row (pd.Series): [Row from pandas dataframe (pandas series)]
            columns (List[str]): [List of columns (str) in table]
            presentFeatures (List[str]): [List of present features (str) in table]
            featureDict (Dict): [A dictionary that maps the number of occurrences of a feature in a column. key: feature (str), value: # of occurrences (int)]

        Returns:
            [Dict]: [A dictionary that maps the number of occurrences of a feature in a column. key: feature (str), value: # of occurrences (int)]
        """
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

    def generate(self, binTable: pd.DataFrame, cleanTable: pd.DataFrame):
        """[Function for generating data signatures from table given the presence/absence of data]

        Args:
            binTable (pd.DataFrame): [binarized dataframe generated from raw dataframe]
            cleanTable (pd.DataFrame): [cleaned dataframe geneated from raw dataframe]

        Returns:
            [type]: [
                signaturedict: dictionary
                key: signature
                value(s):
                    count: # of features (int)
                    presentFeatures: list of features (str)
                    missingFeatures: list of features (str)
                    featureDict:
                        key: feature (str)
                        values:
                            dictionary of {(feature): {value}}  and their counts
            ]
        """

        #print('Generating dictionary of signatures for table.')
        columns = binTable.columns
        signatureDict = {}
        
        for index, row in binTable.iterrows():
            signature = ''.join(map(str, row.values.tolist()))
            
            # If this signature does not exist
            if signature not in signatureDict:
                
                # Identify Present/Missing features
                present, missing = self.getPresentColumns(signature, columns)
                # Generate and update number of different data types in the feature dictionary
                featureDict = {i: {} for i in present}
                featureDict = self.countTypes(cleanTable.iloc[index], columns, present, featureDict)
                
                signatureDict[signature] = {
                    'count': 1,
                    'presentFeatures': present,
                    'missingFeatures': missing,
                    'featureDict': featureDict
                }
            else:
                signatureDict[signature]['count'] += 1
                signatureDict[signature]['featureDict'] = self.countTypes(cleanTable.iloc[index], columns, signatureDict[signature]['presentFeatures'], signatureDict[signature]['featureDict'])

        return signatureDict

    def generateSignatures(self, exactMatches: List[str] = [], regexes: List[str] = [], removeDuplicates:  bool = True, isInvariant: bool = True, removeNaN: bool = True):

        """Function for generating a dictionary of data signature

        Args:
            exactMatches (List[str], optional): [List of features to remove from the table]. Defaults to [].
            regexes (List[str], optional): [List of regular expressions. If a feature matches a regular expression, it will be removed from the table.]. Defaults to [].
            removeDuplicates (bool, optional): [Boolean for whether duplicates should be removed.]. Defaults to True.
            isInvariant (bool, optional): [Boolean to check whether invariant columns should be removed.]. Defaults to True.
            removeNaN (bool, optional): [Determines if NaN values should be converted to an empty string]. Defaults to True.
        """

        self.cleanedData = self.cleanData(exactMatches=exactMatches, regexes=regexes, removeDuplicates=removeDuplicates, isInvariant=isInvariant)
        self.features = list(self.cleanedData)
        self.binData = self.binarizeData(self.cleanedData, removeNaN=removeNaN)
        self.signatureDict = self.generate(self.binData, self.cleanedData)
        featureMap = {}
        for key, value in self.signatureDict.items():
            featureMap[tuple(sorted(list(value['presentFeatures'])))] = key
        self.featureMap = featureMap

    def findUniques(self, threshold: int = 1):
        """[Function for finding unique values for a signature. featureValueCounts stores the number of times a value shows up in other signatures. i.e. if the item is ('status', 3): 5, the vlaue status code of 3 shows up in 5 other signatures]

        Args:
            threshold (int, optional): [Value that defines the threshold for what a unique value within a column should be]. Defaults to 1.
        """
        if threshold < 1:
            print("You set a threshold less than 1, automatically set to 1.")
            threshold = 1

        uniques = {}

        featureValueCounts = {}
        for signature, properties in self.signatureDict.items():
            featureDict = properties['featureDict']
            uniqueFeatures = []
            for feature, values in featureDict.items():
                if 0 < len(values.keys()) <= threshold:
                    uniqueFeatures.append({feature: list(values.keys())[0]})
                    key = (feature, list(values.keys())[0])
                    if key in featureValueCounts:
                        featureValueCounts[key] += 1
                    else:
                        featureValueCounts[key] = 1
            uniques[signature] = uniqueFeatures
        self.uniqueFeatures = uniques
        self.featureValueCounts = featureValueCounts