REVOKE ALL ON TABLE public.scientific_event FROM PUBLIC;
REVOKE ALL ON TABLE public.scientific_event FROM bioworld_writer;
REVOKE ALL ON FUNCTION public.reject_scientific_event_mutation() FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO bioworld_writer;
GRANT SELECT, INSERT ON TABLE public.scientific_event TO bioworld_writer;
