import setuptools

with open('README.md','r') as rm:
    l_description = rm.read()

setuptools.setup(
    name = 'python_ns_skeleton',
    version = '0.21',
    packages = ['python_ns_skeleton'],
    author = 'Nikolaev Andrey',
    author_email = 'nikolaev.a.v@cniiag.local',
    description = 'Ns-skeleton for python packages',
    python_requires='>=3',
    long_description = l_description,
    install_requires = ['tornado', 'msgpack'],
    classifiers = [
        "Programming Language :: Python :: 3",
    ],
)