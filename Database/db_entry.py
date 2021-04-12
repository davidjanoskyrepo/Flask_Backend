class DataSet():
    """
    Abstract data base entry representing a data set with api calls as follows
    """
    def __init__(self, adapter=None):
        self.database = adapter

    def find_all(self, selector):
        return self.database.find_all(selector)
 
    def find(self, selector):
        return self.database.find(selector)
 
    def create(self, set):
        return self.database.create(set)
  
    def update(self, selector, set):
        return self.database.update(selector, set)
  
    def delete(self, selector):
        return self.database.delete(selector)
