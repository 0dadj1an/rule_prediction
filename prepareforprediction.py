__author__ = "ivo hrbacek"
__credits__ = ["ivosh", "laura"]
__version__ = "1.0"
__maintainer__ = "ivo hrbacek"
__email__ = "ihr@actinet.cz"
__status__ = "testing"

"""
testing code for finding similarity in FW policy based on numeric data (SRC/DST/PORT)
"""


from sklearn import datasets,tree # Decision Tree alg
from sklearn.neighbors import KNeighborsClassifier # KNeighbors classifier
from ipaddress import IPv4Address
import binascii
import socket
import sys
import time

"""
DT:
https://scikit-learn.org/stable/modules/generated/sklearn.tree.DecisionTreeClassifier.html
https://chiragsehra42.medium.com/decision-trees-explained-easily-28f23241248
https://en.wikipedia.org/wiki/Decision_tree_learning

"""




def decimal_to_int(initItem):
    """
    translate dec to integer
    """
    return int(IPv4Address(initItem))

def decimal_to_binary(initItem):
    """
    translate decimal to binary
    """
    return (''.join([bin(int(x)+256)[3:] for x in initItem.split('.')]))
    
def decimal_to_hex(initItem):
    """
    translate decimal to hex
    """
    if initItem =="0":
        print ("fix convert of hex 0 to bin first or use different value, leaving..")
        sys.exit(1)
    return hex_to_binary(binascii.hexlify(socket.inet_aton(initItem)))

def hex_to_binary(hexItem):
    """
    translate hex to binary
    """
    # importatnt, does not convert 0 to bin!! avoid zero for hex
    n = int(hexItem, 16)  
    bStr = '' 
    while n > 0: 
        bStr = str(n % 2) + bStr 
        n = n >> 1    
    res = bStr 
    return res


def generate_features(type, list):
    """
    generate features, that means all rules converted to binary to be able search for similar ones via alg
    """
    features = []
    
    if type=="bin":
        for item in list:
            help_list= []
            for iteminner in item:
                help_list.append(decimal_to_binary(iteminner))
            features.append(help_list)
            
    if type=="hex":
        for item in list:
            help_list= []
            for iteminner in item:
                help_list.append(decimal_to_hex(iteminner))
            features.append(help_list)

    return features

    

def predictDtree(features,lables,predict_rule):
    """
    fill Decision tree alg with features (converted policy) and lables (new rule to be validated to find possible similarity match)
    """
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(features, lables)
    return (clf.predict(predict_rule))


def predictKtree(features,lables,predict_rule):
    """
    fill KNeighborsClassifier alg with features (converted policy) and lables (new rule to be validated to find possible similarity match)
    """
    neigh = KNeighborsClassifier(n_neighbors=1)
    neigh.fit(features, lables)
    return (neigh.predict(predict_rule))

def create_lables(len):
    lables =[]
    i=1
    for x in range(len):
        lables.append(str(i))
        i = i+1
    return lables


def main():
    
    # aditional numeric codes
    #6 means UDP
    #7 means TCP
    #255 means any
    #1 accept
    #2 deny
        
    """
    example of testing rulebase, just 4 rules, create how many you want    
    """
    rules = [
        ["192.168.10.0","255.255.255.0", "10.20.2.0", "255.255.255.0", "6", "123", "1"],
        ["192.168.11.0","255.255.255.0", "10.3.2.0", "255.255.255.0", "7", "8080", "2"],
        ["192.168.12.0","255.255.255.0", "10.240.2.0", "255.255.255.0", "7", "443", "2"],
        ["192.168.13.0","255.255.255.0", "10.5.2.0", "255.255.255.0", "6", "53", "2"],
    ]

    """
    predicting rule
    """
    predict_rule =[
        ["192.168.0.0","255.255.0.0", "10.5.0.0", "255.255.0.0", "6", "53", "1"],
    
    ]
 
 
    """
    run and predict
    """
    
    print ("Rules:")
    for item in rules:
        print (item)
    print ("")
    print ("New rule:")
    print (predict_rule)
    print ("")

    # construct and predict

    features_bin = generate_features("bin",rules)
    features_hex = generate_features("hex",rules)
    predict_rule_bin = generate_features("bin",predict_rule)
    predict_rule_hex = generate_features("hex",predict_rule)

    # print converted
    print ("version 1:")
    print ("Print decimal to binary converted items:")

    for item in features_bin:
        print (item)


    print ("Results decimal to binary:")
    print ("")
    dt_bin=predictDtree(features_bin, create_lables(len(features_bin)),predict_rule_bin)
    kn_cls=predictKtree(features_bin, create_lables(len(features_bin)),predict_rule_bin)
    print ("DecisionTreeClassifier predict Decimal to bin: {}".format(dt_bin))
    print ("KNeighborsClassifier predict Decimal to bin: {}".format(kn_cls))
    
    if dt_bin[0]==kn_cls[0]:
        index_in_rules=int(dt_bin[0])
        print ("")
        print ("Found same similar rule in both algs, similar rule is:\n{}".format(rules[index_in_rules-1]))
    else:
        print ("Different result, decide what alg is better, this need some analytic research")

    # print converted
    print ("")
    print ("")
    print ("")
    print ("")
    
    time.sleep(1)
    print ("version 2:")
    print ("Print decimal to hex and to binary items:")

    for item in features_hex:
        print (item)


    print ("Results decimal to hex:")
    print ("")
    print ("")
    dt_hex=predictDtree(features_hex, create_lables(len(features_hex)),predict_rule_hex)
    kn_cls_hex=predictKtree(features_hex, create_lables(len(features_hex)),predict_rule_hex)
    print ("DecisionTreeClassifier predict Decimal to bin: {}".format(dt_hex))
    print ("KNeighborsClassifier predict Decimal to bin: {}".format(kn_cls_hex))
    
    if dt_hex[0]==kn_cls_hex[0]:
        index_in_rules=int(dt_hex[0]) # remember -1 in list indexing
        print ("")
        print ("Found same similar rule in both algs, similar rule is:\n{}".format(rules[index_in_rules-1]))
    else:
        print ("Different result, decide what alg is better, this need some analytic research")
        
        
    print ("")
    print ("")    
    print ("Run this use case multiple times, you will see that results may be different every run with same input values!!")
   
if __name__ == "__main__":
    
    main()


