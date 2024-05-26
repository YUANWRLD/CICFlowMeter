# -*- coding: utf-8 -*-

import io
import os

from setuptools import find_packages, setup

# Package meta-data.
NAME = "cicflowmeter"
DESCRIPTION = "CICFlowMeter implementation with extra feature: \"Slow HTTP Attack Detect\"(The original project site is at \"https://gitlab.com/hieulw/cicflowmeter\", This project is the modified version)"
AUTHOR = "yuan"
REQUIRES_PYTHON = ">=3.7.0"
VERSION = "1.0.0"


def get_requirements(source: str = "requirements.txt"):
    requirements = []
    with open(source) as f:
        for line in f:
            package, _, comment = line.partition("#")
            package = package.strip()
            if package:
                requirements.append(package)

    return requirements


REQUIRED = get_requirements("requirements.txt")

here = os.path.abspath(os.path.dirname(__file__))

# Import the README and use it as the long-description.
# Note: this will only work if 'README.md' is present in your MANIFEST.in file!
try:
    with io.open(os.path.join(here, "README.md"), encoding="utf-8") as f:
        long_description = "\n" + f.read()
except FileNotFoundError:
    long_description = DESCRIPTION

# Load the package's __version__.py module as a dictionary.
about = {}
if not VERSION:
    prefix = "src"
    project_slug = NAME.lower().replace("-", "_").replace(" ", "_")
    with open(os.path.join(here, prefix, project_slug, "__init__.py")) as f:
        exec(f.read(), about)
else:
    about["__version__"] = VERSION

# Where the magic happens:
setup(
    name=NAME,
    version=about["__version__"],
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type="text/markdown",
    author=AUTHOR,
    python_requires=REQUIRES_PYTHON,
    packages=find_packages("src"),
    # package_dir={"cicflowmeter": "src/cicflowmeter"},
    package_dir={"": "src"},
    entry_points={
        "console_scripts": ["cicflowmeter=cicflowmeter.sniffer:main"],
    },
    install_requires=REQUIRED,
    include_package_data=True,
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
)
