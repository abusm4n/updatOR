import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Data Preparation
years = np.arange(2016, 2023+1)
categories = ['Confidentiality', 'Integrity', 'Availability', 'Complexity']
num_points = 19

# Generate random data
np.random.seed(42)
data = {
    'Year': np.concatenate([np.random.choice(years, num_points) for _ in categories]),
    'Category': np.tile(categories, num_points),
    'Vulnerability': np.concatenate([np.random.choice(['High', 'Medium'], num_points) for _ in categories])
}

# Create a DataFrame
df = pd.DataFrame(data)

# Color mapping
color_map = {'High': 'red', 'Medium': 'yellow'}
df['Color'] = df['Vulnerability'].map(color_map)

# Plotting with seaborn relplot
plt.figure(figsize=(10, 6))
sns.relplot(data=df, x='Category', y='Year', hue='Vulnerability', palette=color_map, aspect=1.5, s=100)

# Customizing the plot
plt.title('Vulnerability Distribution from 2016 to 2023')
plt.xlabel('Category')
plt.ylabel('Year')
plt.grid(True)

# Show the plot
plt.show()
