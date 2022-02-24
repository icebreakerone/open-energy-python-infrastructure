
# Open Energy Jupyter Notebook Examples
[Open Energy](https://openenergy.org.uk) classes data as [Open, Shared or Closed](https://icebreakerone.org/open-shared-closed/). **Open data** is available to everyone for free without restriction. **Shared data** may be used by validated Open Energy member organisations subject to conditions set by the data owner. **Closed data** requires custom arrangements in order to be accessed.

[Open Energy Search](https://data.openenergy.org.uk/dataset-list) is a web application and API used to discover datasets indexed by Open Energy based on their metadata. 

These Jupyter Notebooks demonstrate the use of Open Energy Search and [Open Energy Access Control](https://docs.openenergy.org.uk/main/access_control_specification.html) to find and retrieve Open and Shared datasets for analysis or display.

### open_dataset_retrieval.ipynb
Demonstrates using Open Energy Search from a notebook to find a dataset, check its metadata, download and display it.

[View in Google Colab](https://colab.research.google.com/github/icebreakerone/open-energy-python-infrastructure/blob/main/examples/jupyter/open_dataset_retrieval.ipynb)

### setting_up_a_shared_data_connection.ipynb
A walkthrough of the process to register with Open Energy, then use your account to generate the certificates necessary to access Shared dataset

[View in Google Colab](https://colab.research.google.com/github/icebreakerone/open-energy-python-infrastructure/blob/main/examples/jupyter/setting_up_a_shared_data_connection.ipynb)

### shared_dataset_retrieval.ipynb
Demonstrates using Open Energy Search from a notebook to find a dataset, check its metadata to find it is a Shared data set, then use the configuration saved in `setting_up_a_shared_data_connection.ipynb` to access it securely

[View in Google Colab](https://colab.research.google.com/github/icebreakerone/open-energy-python-infrastructure/blob/main/examples/jupyter/shared_dataset_retrieval.ipynb)
