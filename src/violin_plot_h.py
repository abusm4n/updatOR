import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Load dataset from CSV
dataset = pd.read_csv("csv_sw_fw.csv")

# Create the box plot
sns.set_theme(style="whitegrid")
#sns.boxplot(data=dataset, x='base', orient='h', y='year', hue='type')
#sns.boxplot(data=dataset, x='impact', orient='h', y='year', hue='type')
sns.violinplot(data=dataset, x='exploitability', orient='h', y='year', hue='type')


# Set the x-axis limits from 1 to 10
#plt.xlim(0, 10)

# Save the plot as a PDF
# plt.savefig("base_box_plot.pdf", format='pdf')
#plt.savefig("impact_box_plot.pdf", format='pdf')
plt.savefig("exploitability_box_plot_new.pdf", format='pdf')



# Show the plot
plt.show()
