interface JSONResponseBase<Datum = object> {
  success: boolean;
  error: null | string;
  content: null | Datum;
}
