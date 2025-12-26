import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Load dataset from CSV
dataset = pd.read_csv("csv_sw_fw.csv")



# Set the size of the figure
#plt.figure(figsize=(3.5, 4.8))  # Adjust the figure size as needed

# Create the box plot
sns.set_theme(style="whitegrid")
#sns.violinplot(data=dataset, x='year',  y='base', hue='type')
#sns.violinplot(data=dataset, x='year',  y='impact', hue='type')
sns.violinplot(data=dataset, x='year',  y='base', hue='type')



# Customize the legend
plt.legend(title='')
plt.xlabel('')

# Save the plot as a PDF
plt.savefig("base_violin_plot_new.pdf", format='pdf' ,bbox_inches='tight')
#plt.savefig("impact_violin_plot_new.pdf", format='pdf' ,bbox_inches='tight')
#plt.savefig("exploitability_violin_plot_new.pdf", format='pdf' ,bbox_inches='tight')

# Show the plot
plt.show()