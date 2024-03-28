from distutils.core import setup

setup(name='tenable-aws-sechub',
      version='2.0',
      description=('Tenable Vulnerability Management to AWS Security Hub '
                   'finding uploader.'
                   ),
      author='Tenable, Inc.',
      author_email='smcgrath@tenable.com',
      url='https://github.com/tenable/Security-Hub',
      license='MIT',
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
      ],
      keywords='tenable, tenable.io, aws security hub',
      packages=['tenable_aws_sechub'],
      install_requires=[
        'arrow>=1.3.0',
        'restfly>=1.4.5',
        'typer>=0.9.0',
        'tomlkit>=0.12.4',
        'boto3>=1.34.68',
        'rich>=13.3.1',
        'pytenable>=1.4.20',
      ],
      entry_points={
        'console_scripts': ['tvm2aws=tenable_aws_sechub.cli:app'],
      }
      )
