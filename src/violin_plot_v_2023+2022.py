import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Load dataset from CSV
dataset = pd.read_csv("csv_2023+2022.csv")

# Set the size of the figure
plt.figure(figsize=(3.5, 4.8))  # Adjust the figure size as needed


# Create the violin plot with reduced width
sns.set_theme(style="whitegrid")
#sns.violinplot(data=dataset, x='year', y='base', hue='type')
#sns.violinplot(data=dataset, x='year', y='impact', hue='type')
sns.violinplot(data=dataset, x='year', y='exploitability', hue='type')

# Customize the legend
plt.legend(title='')
plt.xlabel('')

# Save the plot as a PDF
#plt.savefig("base_violin_plot_23_22.pdf", format='pdf',bbox_inches='tight')
#plt.savefig("impact_violin_plot_23_22.pdf", format='pdf',bbox_inches='tight')
plt.savefig("exploitability_violin_plot_23_22.pdf", format='pdf',bbox_inches='tight')

# Show the plot
plt.show()
