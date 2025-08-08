import AboutData from "../../../data/global/about.json";

const Blockquote = () => {
    return (
        <div className="blockquote-area">
            <div className="container">
                <div className="row">
                    <div className="col-lg-12" data-aos="fade-up">
                        <blockquote className="blockquote-style">
                            <p
                                dangerouslySetInnerHTML={{
                                    __html: AboutData[3].excerpt,
                                }}
                            />
                            <div className="author-info">
                                <span className="name">
                                    {AboutData[3].name}
                                </span>
                                <span className="job">
                                    {AboutData[3].designation}
                                </span>
                            </div>
                        </blockquote>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Blockquote;
