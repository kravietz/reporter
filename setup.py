import setuptools

version = __import__('reporter').__version__
packages = setuptools.find_packages()
print(packages)

setuptools.setup(
    name="reporter",
    version=version,
    author="Pawel Krawczyk",
    author_email="pawel.krawczyk@hush.com",
    description="CSP report server",
    url="https://bitbucket.org/kravietz/reporter/src/master/",
    packages=packages,
    install_requires=('sanic',),
    # psycopg and aiohttp are installed from debs in snap/snapcraft.yaml
    #    install_requires=('psycopg2-binary', 'sanic', 'aiohttp', 'systemd-python'),
    entry_points={'console_scripts': ('reporter = reporter.server:main',)},
    license='All rights reserved',
)
