# for micropython compatibility

class UserList:
    def __init__(self, initlist=None):
        self.data = list(initlist) if initlist is not None else []

    # Support basic list operations
    def __getitem__(self, index):
        return self.data[index]

    def __setitem__(self, index, value):
        self.data[index] = value

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(self.data)

    def append(self, item):
        self.data.append(item)

    def extend(self, other):
        self.data.extend(other)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.data!r})"
