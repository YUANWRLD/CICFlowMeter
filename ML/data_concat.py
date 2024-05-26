import glob
import pandas as pd
import os

path = './model_data/preprocessdata/'
allfile = glob.glob(os.path.join(path, '*.csv'))
data_set = []

for file in allfile:
    df = pd.read_csv(file)
    data_set.append(df)

result = pd.concat(data_set, ignore_index=True)
result.to_csv('train_data_v1.csv', index=False)