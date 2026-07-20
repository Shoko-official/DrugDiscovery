REVOKE ALL ON SCHEMA public FROM bioworld_reader;
REVOKE ALL ON TABLE public.scientific_event FROM bioworld_reader;
REVOKE ALL ON FUNCTION public.reject_scientific_event_mutation()
  FROM bioworld_reader;

GRANT USAGE ON SCHEMA public TO bioworld_reader;
GRANT SELECT ON public.scientific_event TO bioworld_reader;
