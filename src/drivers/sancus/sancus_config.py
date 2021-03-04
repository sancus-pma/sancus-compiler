
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
from yaml import YAMLError

SM_CONFIG_DEFAULT_DISALLOW_OUTCALLS=None
SM_CONFIG_DEFAULT_SM_ENTRY=""
SM_CONFIG_DEFAULT_SM_MMIO_ENTRY=""
SM_CONFIG_DEFAULT_SM_EXIT=""
SM_CONFIG_DEFAULT_SM_ISR=""
SM_CONFIG_DEFAULT_PERIPHERAL_OFFSET=0

class SmParserError(Exception):
    """ 
    Raised when there is an error during parsing of the config file.
    """
    pass

class SmConfigMalformedError(Exception):
    """
    Raised when there is an error in the config itself.
    """
    pass

class SmConfigParser:
    """
    Parses a config file from a given path as passed through the command line.
    Returns a dict of {'sm_name': SmConfig for each sm_name in sms}
    Whenever a dict does not define a parameter or a specific SM, default values are used.
    """
    def __init__(self,config_file_path, sms, project_dir, sancus_dir):
        sm_config_dict = {}

        if config_file_path != '':
            # load yaml
            with open(config_file_path, 'r') as stream:
                yaml_config = stream.read()

            # Substitute $PATH in the yaml file for args.project_path
            yaml_config = yaml_config.replace("$PROJECT", project_dir)

            # Substitute $SANCUS in the yaml for sancus datapath
            yaml_config = yaml_config.replace("$SANCUS", sancus_dir)

            # Parse to yaml into sm_config_dict
            try:
                sm_config_dict = load(yaml_config, Loader=Loader)
            except YAMLError:
                raise SmParserError('Error loading YAML file ' + config_file_path)
            
            # flatten dicts
            for k,v in sm_config_dict.items():
                final_map = {}
                if v is not None:
                    for d in v:
                        final_map.update(d)
                    sm_config_dict[k]=final_map

        # Build final sm config dict with name : SmConfig mapping
        self._sm_config = {}
        self._count = len(sms)

        num_peripheral_offset_set = 0
        for name in sms:
            this_sm_config = {}
            if name in sm_config_dict:
                this_sm_config = sm_config_dict[name] 

            new_config = SmConfig(name, this_sm_config)

            if hasattr(new_config, 'peripheral_offset'):
                num_peripheral_offset_set += 1

            self._sm_config[name] = new_config

        if num_peripheral_offset_set > 1:
            raise SmConfigMalformedError('More than one SM with peripheral offset!')
        
    @property
    def sm_config(self):
        return self._sm_config

    """
    Method to allow a sorting of the SMs.
    This is useful to e.g. take the peripheral offset into account and manage to
    sort the SM that enables this offset into first place.
    """
    def sort_sm_name(self, sm_name):
        if sm_name in self._sm_config and hasattr(self._sm_config[sm_name], 'peripheral_offset'):
            # If SM has peripheral offset set, place it first
            return 1
        else:
            # We don't really care about the order of SMs otherwise
            return 2

class SmConfig:
    _contains_config = False

    """
    Python class representing a Sancus module as 
    configured via an sm-config.yml file
    """
    def __init__ (self, sm_name, config_dict):
        self._name = sm_name
        self._config_dict = config_dict if config_dict is not None else {}

        """
        Internal init function to safely parse a key from the config dict
        with a given default value as backup.
        """
        def _safe_config_parse(name, default_val):
            if name in self._config_dict:
                self._contains_config = True
                return self._config_dict[name]
            else:
                return default_val

        # Parse all implemented options in the config dict with the safe parser
        self._disallow_outcalls = _safe_config_parse('disallow_outcalls', SM_CONFIG_DEFAULT_DISALLOW_OUTCALLS)
        self._sm_entry = _safe_config_parse('sm_entry', SM_CONFIG_DEFAULT_SM_ENTRY)
        self._sm_mmio_entry = _safe_config_parse('sm_mmio_entry', SM_CONFIG_DEFAULT_SM_MMIO_ENTRY)
        self._sm_exit  = _safe_config_parse('sm_exit',  SM_CONFIG_DEFAULT_SM_EXIT)
        self._sm_isr   = _safe_config_parse('sm_isr' ,  SM_CONFIG_DEFAULT_SM_ISR)
        self._peripheral_offset = _safe_config_parse('peripheral_offset', 0)

    """
    Getters as properties for all class variables.
    Implemented to also be usable with hasattr
    """
    
    @property
    def name(self):
        return self._name

    @property
    def disallow_outcalls(self):
        if self._disallow_outcalls != SM_CONFIG_DEFAULT_DISALLOW_OUTCALLS:
            return self._disallow_outcalls
        else:
            raise AttributeError

    @property
    def sm_entry(self):
        if self._sm_entry != SM_CONFIG_DEFAULT_SM_ENTRY:
            return self._sm_entry
        else:
            raise AttributeError

    @property
    def sm_mmio_entry(self):
        if self._sm_mmio_entry != SM_CONFIG_DEFAULT_SM_MMIO_ENTRY:
            return self._sm_mmio_entry
        else:
            raise AttributeError


    @property
    def sm_exit(self):
        if self._sm_exit != SM_CONFIG_DEFAULT_SM_EXIT:
            return self._sm_exit
        else:
            raise AttributeError

    @property
    def sm_isr(self):
        if self._sm_isr != SM_CONFIG_DEFAULT_SM_ISR:
            return self._sm_isr
        else:
            raise AttributeError

    @property
    def peripheral_offset(self):
        if self._peripheral_offset != SM_CONFIG_DEFAULT_PERIPHERAL_OFFSET:
            return abs(self._peripheral_offset)
        else:
            raise AttributeError
    
    def __str__(self):
        if self._contains_config:
            s = '' + self._name + ':\n'
            if hasattr(self, 'disallow_outcalls'): s+= '\t\t Disallow outcalls: ' + str(self._disallow_outcalls) + '\n'
            if hasattr(self, 'sm_entry'): s += '\t\t SM_ENTRY: ' + self._sm_entry  + '\n'
            if hasattr(self, 'sm_mmio_entry'): s += '\t\t SM_MMIO_ENTRY: ' + self._sm_mmio_entry  + '\n'
            if hasattr(self, 'sm_exit'): s += '\t\t SM_EXIT: ' + self._sm_exit  + '\n'
            if hasattr(self, 'sm_isr'): s += '\t\t SM_ISR: ' + self._sm_isr  + '\n'
            if hasattr(self, 'peripheral_offset'): s += '\t\t Peripheral Offset: ' + str(self._peripheral_offset)  + '\n'
        else:
            s = 'No YAML config provided.'
        return s